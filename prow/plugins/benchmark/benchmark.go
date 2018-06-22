/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package benchmark

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/test-infra/prow/config"
	"k8s.io/test-infra/prow/github"
	"k8s.io/test-infra/prow/kube"
	"k8s.io/test-infra/prow/pjutil"
	"k8s.io/test-infra/prow/pluginhelp"
	"k8s.io/test-infra/prow/plugins"
	"k8s.io/test-infra/prow/repoowners"
)

const pluginName = "benchmark"
const repoName = "sipian/prometheus"
const projectName = "gcr.io/prometheus-test-204522"
const buildPRJobName = "build-PR-images"
const benchmarkName = "start-benchmark"
const cancelBenchmarkJobName = "cancel-benchmark"
const prowJobPRNumber = "PR_NUMBER"
const prowJobPrometheus1Name = "PROMETHEUS_1_NAME"
const prowJobPrometheus1Image = "PROMETHEUS_1_IMAGE"
const prowJobPrometheus2Name = "PROMETHEUS_2_NAME"
const prowJobPrometheus2Image = "PROMETHEUS_2_IMAGE"

var (
	benchmarkLabel    = "benchmark"
	benchmarkRe       = regexp.MustCompile(`(?mi)^/benchmark\s+(release|pr)\s*$`)
	benchmarkCancelRe = regexp.MustCompile(`(?mi)^/benchmark\s+cancel\s*$`)
)

func init() {
	plugins.RegisterIssueCommentHandler(pluginName, handleIssueComment, helpProvider)
	// plugins.RegisterPullRequestHandler(pluginName, func(pc plugins.PluginClient, pe github.PullRequestEvent) error {
	// 	return handlePullRequest(pc.GitHubClient, pe, pc.Logger)
	// }, helpProvider)
}

func helpProvider(config *plugins.Configuration, enabledRepos []string) (*pluginhelp.PluginHelp, error) {
	// The Config field is omitted because this plugin is not configurable.
	pluginHelp := &pluginhelp.PluginHelp{
		Description: "The benchmark plugin starts prometheus benchmarking tool(prombench).",
	}
	pluginHelp.AddCommand(pluginhelp.Command{
		Usage:       "/benchmark [release|pr]",
		Description: "Starts prometheus benchmarking tool. With `release` current master will be compared with previous release. With `pr`, PR will be compared with current master.",
		Featured:    true,
		WhoCanUse:   "Members whose Github handle is present in OWNER file.",
		Examples:    []string{"/benchmark release", "/benchmark pr", "/benchmark cancel"},
	})
	return pluginHelp, nil
}

type githubClient interface {
	IsMember(owner, login string) (bool, error)
	AddLabel(owner, repo string, number int, label string) error
	AssignIssue(owner, repo string, number int, assignees []string) error
	CreateComment(owner, repo string, number int, comment string) error
	RemoveLabel(owner, repo string, number int, label string) error
	GetIssueLabels(org, repo string, number int) ([]github.Label, error)
	GetPullRequest(org, repo string, number int) (*github.PullRequest, error)
	GetRef(org, repo, ref string) (string, error)
	GetPullRequestChanges(org, repo string, number int) ([]github.PullRequestChange, error)
	ListIssueComments(org, repo string, number int) ([]github.IssueComment, error)
	DeleteComment(org, repo string, ID int) error
	BotName() (string, error)
}

type kubeClient interface {
	CreateProwJob(kube.ProwJob) (kube.ProwJob, error)
}

type client struct {
	GitHubClient githubClient
	KubeClient   kubeClient
	Config       *config.Config
	Logger       *logrus.Entry
}

func getClient(pc plugins.PluginClient) client {
	return client{
		GitHubClient: pc.GitHubClient,
		Config:       pc.Config,
		KubeClient:   pc.KubeClient,
		Logger:       pc.Logger,
	}
}

func handleIssueComment(pc plugins.PluginClient, ic github.IssueCommentEvent) error {
	return handle(getClient(pc), pc.OwnersClient, ic)
}

func handle(c client, ownersClient repoowners.Interface, ic github.IssueCommentEvent) error {
	// Only consider PRs and new comments.
	c.Logger.Infof("Inside benchmark plugin")
	if ic.Issue.PullRequest == nil || ic.Action != github.IssueCommentActionCreated {
		return nil
	}
	c.Logger.Infof("Started benchmark plugin")

	org := ic.Repo.Owner.Login
	repo := ic.Repo.Name
	number := ic.Issue.Number
	commentAuthor := ic.Comment.User.Login

	// If we create an "/benchmark" comment, add benchmark if necessary.
	// If we create a "/benchmark cancel" comment, remove benchmark if necessary.
	wantBenchmark := false
	if benchmarkRe.MatchString(ic.Comment.Body) {
		wantBenchmark = true
	} else if benchmarkCancelRe.MatchString(ic.Comment.Body) {
		wantBenchmark = false
	} else {
		return nil
	}

	// check if comment author is authorized to start benchmarking
	ro, err := loadRepoOwners(c.GitHubClient, ownersClient, org, repo, number)
	if err != nil {
		return err
	}
	if !loadReviewers(ro, []string{"OWNERS"}).Has(commentAuthor) {
		resp := "adding benchmark is restricted to approvers in OWNERS files."
		c.Logger.Infof("Reply to /benchmark request with comment: \"%s\".", resp)
		return c.GitHubClient.CreateComment(org, repo, number, plugins.FormatICResponse(ic.Comment, resp))
	}

	benchmarkOption := "pr"
	if wantBenchmark {
		if strings.Contains(ic.Comment.Body, "release") {
			benchmarkOption = "release"
		}
	}
	c.Logger.Infof("Checked repo status %s", benchmarkOption)

	hasBenchmarkLabel := false
	labels, err := c.GitHubClient.GetIssueLabels(org, repo, number)
	if err != nil {
		return fmt.Errorf("Failed to get the labels on %s/%s#%d %v.", org, repo, number, err)
	}
	for _, candidate := range labels {
		if candidate.Name == benchmarkLabel {
			hasBenchmarkLabel = true
			break
		}
	}

	c.Logger.Infof("Has label :: %d", hasBenchmarkLabel)

	if wantBenchmark {
		// Delete all the previous benchmarking comments to avoid confusion
		botname, err := c.GitHubClient.BotName()
		if err != nil {
			fmt.Errorf("Failed to get bot name.")
		}
		c.Logger.Infof("BOTNAME : %s", botname)
		comments, err := c.GitHubClient.ListIssueComments(org, repo, number)
		if err != nil {
			fmt.Errorf("Failed to get the list of issue comments on %s/%s#%d.", org, repo, number)
		}
		for _, comment := range comments {
			if comment.User.Login == botname {
				if err := c.GitHubClient.DeleteComment(org, repo, comment.ID); err != nil {
					fmt.Errorf("Failed to delete comment from %s/%s#%d, ID:%d.", org, repo, number, comment.ID)
				}
			}
		}

		c.Logger.Infof("Delete comments")

		// Add benchmark label if not already there
		if !hasBenchmarkLabel {
			c.Logger.Infof("Adding Benchmark label.")
			if err := c.GitHubClient.AddLabel(org, repo, number, benchmarkLabel); err != nil {
				return err
			}
		}

		commentTemplate := `Welcome to Prometheus Benchmarking Tool.

	The two prometheus versions that will be compared are _**master**_ and _**%s**_

	The links to view the ongoing benchmarking metrics will be provided in the logs. 

	The logs can be viewed at the links provided at the end of this conversation

	To cancel the benchmark process comment **/benchmark cancel** .`

		var resp string
		if benchmarkOption == "release" {
			resp = fmt.Sprintf(commentTemplate, "release")
			c.GitHubClient.CreateComment(org, repo, number, plugins.FormatICResponse(ic.Comment, resp))
			err := startBenchmark(c, ic, "master", "quay.io/prometheus/prometheus:master", "release", "quay.io/prometheus/prometheus:latest")
			if err != nil {
				c.GitHubClient.CreateComment(org, repo, number, plugins.FormatICResponse(ic.Comment, fmt.Sprintf("Creation of prombench cluster failed: %v", err)))
				return err
			}
		} else {
			err := buildPRImage(c, ic)
			if err != nil {
				c.GitHubClient.CreateComment(org, repo, number, plugins.FormatICResponse(ic.Comment, "The creation of the docker image for this PR has failed."))
				fmt.Errorf("Failed to create docker image on %s/%s#%d %v.", org, repo, number, err)
				return err
			}
			// resp = fmt.Sprintf(commentTemplate, "pr")
			// c.GitHubClient.CreateComment(org, repo, number, plugins.FormatICResponse(ic.Comment, resp))
			// err := startBenchmark(c, ic, "master", "quay.io/prometheus/prometheus:master", fmt.Sprintf("pr-%d", number), fmt.Sprintf("%s/prombench-PR-image:pr-%d", projectName, number))
			// c.Logger.Infof("Function returned.")
			// if err != nil {
			// 	c.GitHubClient.CreateComment(org, repo, number, plugins.FormatICResponse(ic.Comment, fmt.Sprintf("Creation of prombench cluster failed: %v", err)))
			// 	return err
			// }
		}

	} else {
		if hasBenchmarkLabel {
			c.Logger.Infof("Removing Benchmark label.")
			//TODO Run prowjob to cancel benchmarking
			return c.GitHubClient.RemoveLabel(org, repo, number, benchmarkLabel)
		}
	}
	//  else if !hasBenchmarkLabel && wantBenchmark {

	return nil
}

func startBenchmark(c client, ic github.IssueCommentEvent, prometheus1Name string, prometheus1Image string, prometheus2Name string, prometheus2Image string) error {

	c.Logger.Debugf("Starting prowjob to start benchmarking")
	org := ic.Repo.Owner.Login
	repo := ic.Repo.Name
	number := ic.Issue.Number

	pr, err := c.GitHubClient.GetPullRequest(org, repo, number)
	if err != nil {
		fmt.Errorf("Failed to Get Pull Request %d %v.", number, err)
		return err
	}

	baseSHA, err := c.GitHubClient.GetRef(org, repo, "heads/"+pr.Base.Ref)
	if err != nil {
		fmt.Errorf("Failed to Get Base SHA %v.", err)
		return err
	}

	kr := kube.Refs{
		Org:     org,
		Repo:    repo,
		BaseRef: pr.Base.Ref,
		BaseSHA: baseSHA,
		Pulls: []kube.Pull{
			{
				Number: number,
				Author: pr.User.Login,
				SHA:    pr.Head.SHA,
			},
		},
	}

	var benchmark config.Presubmit
	for _, job := range c.Config.Presubmits[pr.Base.Repo.FullName] {
		if job.Name == benchmarkName {
			// Add environment variables telling which version to benchmark
			c.Logger.Debugf("Inside")
			job.Spec.Containers[0].Env = append(job.Spec.Containers[0].Env, kubeEnv(map[string]string{prowJobPRNumber: strconv.Itoa(number)})...)
			job.Spec.Containers[0].Env = append(job.Spec.Containers[0].Env, kubeEnv(map[string]string{prowJobPrometheus1Name: prometheus1Name})...)
			job.Spec.Containers[0].Env = append(job.Spec.Containers[0].Env, kubeEnv(map[string]string{prowJobPrometheus1Image: prometheus1Image})...)
			job.Spec.Containers[0].Env = append(job.Spec.Containers[0].Env, kubeEnv(map[string]string{prowJobPrometheus2Name: prometheus2Name})...)
			job.Spec.Containers[0].Env = append(job.Spec.Containers[0].Env, kubeEnv(map[string]string{prowJobPrometheus2Image: prometheus2Image})...)
			benchmark = job

			break
		}
	}

	labels := make(map[string]string)
	for k, v := range benchmark.Labels {
		labels[k] = v
	}

	labels[github.EventGUID] = ic.GUID
	pj := pjutil.NewProwJob(pjutil.PresubmitSpec(benchmark, kr), labels)
	c.Logger.WithFields(pjutil.ProwJobFields(&pj)).Info("Creating a new prowjob.")
	if _, err := c.KubeClient.CreateProwJob(pj); err != nil {
		fmt.Errorf("Failed to Create start-benchmark ProwJob %v.", err)
		return err
	}
	return nil
}

func buildPRImage(c client, ic github.IssueCommentEvent) error {

	c.Logger.Debugf("Started prowjob to build PR image")
	org := ic.Repo.Owner.Login
	repo := ic.Repo.Name
	number := ic.Issue.Number

	pr, err := c.GitHubClient.GetPullRequest(org, repo, number)
	if err != nil {
		fmt.Errorf("Failed to Get Pull Request %d %v.", number, err)
		return err
	}

	baseSHA, err := c.GitHubClient.GetRef(org, repo, "heads/"+pr.Base.Ref)
	if err != nil {
		fmt.Errorf("Failed to Get Base SHA %v.", err)
		return err
	}

	var benchmarkJob config.Presubmit
	imageName := fmt.Sprintf("%s/prombench-PR-image:pr-%d", projectName, number)
	for _, job := range c.Config.Presubmits[pr.Base.Repo.FullName] {
		if job.Name == buildPRJobName {
			job.Spec.Containers[0].Env = append(job.Spec.Containers[0].Env, kubeEnv(map[string]string{"PROW_BENCHMARK_DOCKER_IMAGE": imageName})...)
			benchmarkJob = job
			break
		}
	}

	kr := kube.Refs{
		Org:     org,
		Repo:    repo,
		BaseRef: pr.Base.Ref,
		BaseSHA: baseSHA,
		Pulls: []kube.Pull{
			{
				Number: number,
				Author: pr.User.Login,
				SHA:    pr.Head.SHA,
			},
		},
	}

	c.Logger.Infof("Starting %s build.", benchmarkJob.Name)

	labels := make(map[string]string)
	for k, v := range benchmarkJob.Labels {
		labels[k] = v
	}
	labels[github.EventGUID] = ic.GUID
	pj := pjutil.NewProwJob(pjutil.PresubmitSpec(benchmarkJob, kr), labels)
	c.Logger.WithFields(pjutil.ProwJobFields(&pj)).Info("Creating a new prowjob.")
	if _, err := c.KubeClient.CreateProwJob(pj); err != nil {
		fmt.Errorf("Failed to Create start-benchmark ProwJob %v.", err)
		return err
	}
	return nil
}
func loadRepoOwners(ghc githubClient, ownersClient repoowners.Interface, org, repo string, number int) (repoowners.RepoOwnerInterface, error) {
	pr, err := ghc.GetPullRequest(org, repo, number)
	if err != nil {
		return nil, err
	}
	return ownersClient.LoadRepoOwners(org, repo, pr.Base.Ref)
}

// loadReviewers returns all reviewers and approvers from all OWNERS files that
// cover the provided filenames.
func loadReviewers(ro repoowners.RepoOwnerInterface, filenames []string) sets.String {
	reviewers := sets.String{}
	for _, filename := range filenames {
		reviewers = reviewers.Union(ro.Approvers(filename)).Union(ro.Reviewers(filename))
	}
	return reviewers
}

// kubeEnv transforms a mapping of environment variables
// into their serialized form for a PodSpec, sorting by
// the name of the env vars
func kubeEnv(environment map[string]string) []v1.EnvVar {
	var keys []string
	for key := range environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var kubeEnvironment []v1.EnvVar
	for _, key := range keys {
		kubeEnvironment = append(kubeEnvironment, v1.EnvVar{
			Name:  key,
			Value: environment[key],
		})
	}

	return kubeEnvironment
}

/*
type ghLabelClient interface {
	RemoveLabel(owner, repo string, number int, label string) error
	CreateComment(owner, repo string, number int, comment string) error
}

func handlePullRequest(ghc ghLabelClient, pe github.PullRequestEvent, log *logrus.Entry) error {
	if pe.PullRequest.Merged {
		return nil
	}

	if pe.Action != github.PullRequestActionSynchronize {
		return nil
	}

	// Don't bother checking if it has the label...it's a race, and we'll have
	// to handle failure due to not being labeled anyway.
	org := pe.PullRequest.Base.Repo.Owner.Login
	repo := pe.PullRequest.Base.Repo.Name
	number := pe.PullRequest.Number

	var labelNotFound bool
	if err := ghc.RemoveLabel(org, repo, number, benchmarkLabel); err != nil {
		if _, labelNotFound = err.(*github.LabelNotFound); !labelNotFound {
			return fmt.Errorf("failed removing benchmark label: %v", err)
		}

		// If the error is indeed *github.LabelNotFound, consider it a success.
	}
	// Creates a comment to inform participants that benchmark label is removed due to new
	// pull request changes.
	if !labelNotFound {
		log.Infof("Create a benchmark removed notification to %s/%s#%d  with a message: %s", org, repo, number, removeBenchmarkLabelNoti)
		return ghc.CreateComment(org, repo, number, removeBenchmarkLabelNoti)
	}
	return nil
}
*/
