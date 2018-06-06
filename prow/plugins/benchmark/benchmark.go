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
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	// "github.com/prometheus/benchmark"
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

var (
	benchmarkLabel           = "prow-benchmark"
	benchmarkRe              = regexp.MustCompile(`(?mi)^/benchmark\s+(release|pr)\s*$`)
	benchmarkCancelRe        = regexp.MustCompile(`(?mi)^/benchmark\s+cancel\s*$`)
	removeBenchmarkLabelNoti = "New changes are detected. Benchmarking will be stopped."
	benchmarkReleaseNoti     = "Starting benchmarking current master with previous release. Status can be seen at http://COMING-SOON"
	benchmarkPRNoti          = "Starting benchmarking PR with current master. Status can be seen at http://COMING-SOON"
)

func init() {
	plugins.RegisterIssueCommentHandler(pluginName, handleIssueComment, helpProvider)
	plugins.RegisterPullRequestHandler(pluginName, func(pc plugins.PluginClient, pe github.PullRequestEvent) error {
		return handlePullRequest(pc.GitHubClient, pe, pc.Logger)
	}, helpProvider)
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

	benchmarkOption := "pr"
	if wantBenchmark {
		if strings.Contains(ic.Comment.Body, "release") {
			benchmarkOption = "release"
		}

		//TODO move inside labelling logic
		if benchmarkOption == "pr" {
			pj, imageName, err := buildPRImage(c, ic)

			c.Logger.Debugf("Started prowjob to build PR image")

			job := *pj

			if err != nil {
				resp := fmt.Sprintf("Failed to build and push PR image %s. <br/> %v", imageName, err)
				c.GitHubClient.CreateComment(org, repo, number, plugins.FormatICResponse(ic.Comment, resp))
				return fmt.Errorf("Failed to build and push PR image %s %v", imageName, err)
			}

			backoff := 5 * time.Second
			c.Logger.Debugf("Starting Loop")
			for !job.Complete() {
				c.Logger.Debugf("Inside Loop")
				if job.Status.State == kube.FailureState || job.Status.State == kube.AbortedState || job.Status.State == kube.ErrorState {
					c.Logger.Debugf("Condition Failed")
					break
				}
				time.Sleep(backoff)
			}
			c.Logger.Debugf("Ended Loop")
			if job.Status.State == kube.FailureState || job.Status.State == kube.AbortedState || job.Status.State == kube.ErrorState {
				fmt.Errorf("Failed to get build and push PR image %s", imageName)
				resp := fmt.Sprintf("Failed to build and push PR image %s. <br/> [Error Details](%s)", imageName, job.Status.URL)
				c.GitHubClient.CreateComment(org, repo, number, plugins.FormatICResponse(ic.Comment, resp))
				return fmt.Errorf("Failed to get build and push PR image %s %v", imageName, err)
			} else {
				c.Logger.Infof("PR Image %s has been built and pushed", imageName)
				resp := fmt.Sprintf("Image of this PR has been built at [%s](%s)", imageName, imageName)
				c.GitHubClient.CreateComment(org, repo, number, plugins.FormatICResponse(ic.Comment, resp))
			}
		}
	}

	ro, err := loadRepoOwners(c.GitHubClient, ownersClient, org, repo, number)
	if err != nil {
		return err
	}
	if !loadReviewers(ro, []string{"OWNERS"}).Has(commentAuthor) {
		resp := "adding benchmark is restricted to approvers in OWNERS files."
		c.Logger.Infof("Reply to /benchmark request with comment: \"%s\".", resp)
		return c.GitHubClient.CreateComment(org, repo, number, plugins.FormatICResponse(ic.Comment, resp))
	}

	// Only add the label if it doesn't have it, and vice versa.
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
	if hasBenchmarkLabel && !wantBenchmark {
		c.Logger.Infof("Removing Benchmark label.")
		return c.GitHubClient.RemoveLabel(org, repo, number, benchmarkLabel)
	} else if !hasBenchmarkLabel && wantBenchmark {
		resp := benchmarkPRNoti
		if benchmarkOption == "release" {
			resp = benchmarkReleaseNoti
		}
		c.Logger.Infof("Adding Benchmark label.")
		if err := c.GitHubClient.AddLabel(org, repo, number, benchmarkLabel); err != nil {
			return err
		}
		// Delete the benchmark removed noti after the benchmark label is added.
		botname, err := c.GitHubClient.BotName()
		if err != nil {
			fmt.Errorf("Failed to get bot name %v.", err)
		}
		comments, err := c.GitHubClient.ListIssueComments(org, repo, number)
		if err != nil {
			fmt.Errorf("Failed to get the list of issue comments on %s/%s#%d %v.", org, repo, number, err)
		}
		for _, comment := range comments {
			if comment.User.Login == botname && (strings.Contains(comment.Body, removeBenchmarkLabelNoti) || strings.Contains(comment.Body, benchmarkReleaseNoti) || strings.Contains(comment.Body, benchmarkPRNoti)) {
				if err := c.GitHubClient.DeleteComment(org, repo, comment.ID); err != nil {
					fmt.Errorf("Failed to delete comment from %s/%s#%d, ID:%d %v.", org, repo, number, comment.ID, err)
				}
			}
		}
		c.GitHubClient.CreateComment(org, repo, number, plugins.FormatICResponse(ic.Comment, resp))
	}
	return nil
}

func buildPRImage(c client, ic github.IssueCommentEvent) (*kube.ProwJob, string, error) {

	org := ic.Repo.Owner.Login
	repo := ic.Repo.Name
	number := ic.Issue.Number

	pr, err := c.GitHubClient.GetPullRequest(org, repo, number)
	if err != nil {
		fmt.Errorf("Failed to Get Pull Request %d %v.", number, err)
		return nil, "", err
	}

	baseSHA, err := c.GitHubClient.GetRef(org, repo, "heads/"+pr.Base.Ref)
	if err != nil {
		fmt.Errorf("Failed to Get Base SHA %v.", err)
		return nil, "", err
	}

	var benchmarkJob config.Presubmit
	imageName := fmt.Sprintf("%s/prometheus-benchmark:pr-%d-ts-%s", projectName, number, time.Now().Format("20060102150405"))
	for _, job := range c.Config.Presubmits[pr.Base.Repo.FullName] {
		if job.Name == "start-benchmark" {
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
		return nil, "", err
	}
	return &pj, imageName, nil
}

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
