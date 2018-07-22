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
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

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
const buildPRJobName = "build-PR-images"
const startBenchmarkJobName = "start-benchmark"
const cancelBenchmarkJobName = "cancel-benchmark"
const prowJobPRNumber = "PR_NUMBER"
const prowJobPrometheus1Name = "PROMETHEUS_1_NAME"
const prowJobPrometheus1Image = "PROMETHEUS_1_IMAGE"
const prowJobPrometheus2Name = "PROMETHEUS_2_NAME"
const prowJobPrometheus2Image = "PROMETHEUS_2_IMAGE"
const maxTries = 50

var (
	benchmarkLabel        = "benchmark"
	benchmarkPendingLabel = "pending-benchmark-job"
	benchmarkRe           = regexp.MustCompile(`(?mi)^/benchmark\s+(release|pr)\s*([0-9]+\.[0-9]+\.[0-9]+\S*)?\s*$`)
	benchmarkCancelRe     = regexp.MustCompile(`(?mi)^/benchmark\s+cancel\s*$`)
	projectName           = fmt.Sprintf("gcr.io/%s", os.Getenv("PROMBENCH_PROJECT_ID"))
	ingress_ip            = fmt.Sprintf("http://%s", os.Getenv("PROMBENCH_INGRESS_IP"))
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
		Usage:       "/benchmark pr or /benchmark release [version_number(ex:2.3.0-rc.1)|Default:latest]",
		Description: "Starts prometheus benchmarking tool. With `release` current master will be compared with previous release. With `pr`, PR will be compared with current master.",
		Featured:    true,
		WhoCanUse:   "Members whose Github handle is present in OWNER file.",
		Examples:    []string{"/benchmark release", "/benchmark release 2.3.0-rc.1", "/benchmark pr", "/benchmark cancel"},
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
	ListProwJobs(string) ([]kube.ProwJob, error)
	GetProwJob(name string) (kube.ProwJob, error)
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
	if ic.Issue.PullRequest == nil || ic.Action != github.IssueCommentActionCreated {
		return nil
	}

	org := ic.Repo.Owner.Login
	repo := ic.Repo.Name
	number := ic.Issue.Number
	commentAuthor := ic.Comment.User.Login

	// If we create an "/benchmark" comment, add benchmark if necessary.
	// If we create a "/benchmark cancel" comment, remove benchmark if necessary.

	c.Logger.Debugf("Checking benchmark trigger keywords.")
	wantBenchmark := false
	if benchmarkRe.MatchString(ic.Comment.Body) {
		wantBenchmark = true
	} else if benchmarkCancelRe.MatchString(ic.Comment.Body) {
		wantBenchmark = false
	} else {
		return nil
	}

	c.Logger.Debugf("Checking if author is authorized.")
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

	c.Logger.Debugf("Checking which version of Prometheus to benchmark.")
	benchmarkOption := ""
	releaseVersion := ""

	if wantBenchmark {
		group := benchmarkRe.FindStringSubmatch(ic.Comment.Body)
		if group[1] == "pr" {
			benchmarkOption = "pr"
		} else if group[1] == "release" {
			benchmarkOption = "release"
			if group[2] == "" {
				releaseVersion = "latest"
			} else {
				releaseVersion = "v" + group[2]
			}
		} else {
			return nil
		}
	}

	hasBenchmarkLabel := false
	hasBenchmarkPendingLabel := false
	labels, err := c.GitHubClient.GetIssueLabels(org, repo, number)
	if err != nil {
		return fmt.Errorf("Failed to get the labels on %s/%s#%d %v.", org, repo, number, err)
	}
	for _, candidate := range labels {
		if candidate.Name == benchmarkLabel {
			hasBenchmarkLabel = true
		}
		if candidate.Name == benchmarkPendingLabel {
			hasBenchmarkPendingLabel = true
		}
	}

	if hasBenchmarkPendingLabel {
		return c.GitHubClient.CreateComment(org, repo, number, plugins.FormatICResponse(ic.Comment, "Looks like a job is already lined up for this PR.<br/> Please try again once all pending jobs have finished :smiley:"))
	}

	if wantBenchmark {
		if !hasBenchmarkLabel {
			c.Logger.Infof("Adding Benchmark label.")
			if err := c.GitHubClient.AddLabel(org, repo, number, benchmarkLabel); err != nil {
				return err
			}
		} else {
			return c.GitHubClient.CreateComment(org, repo, number, plugins.FormatICResponse(ic.Comment, "Looks like benchmarking is already running for this PR.<br/> You can cancel benchmarking by commenting `/benchmark cancel`. :smiley:"))
		}

		commentTemplate := `Welcome to Prometheus Benchmarking Tool.

The two prometheus versions that will be compared are _**master**_ and _**%s**_

The logs can be viewed at the links provided in the GitHub check blocks at the end of this conversation

After successfull deployment, the benchmarking metrics can be viewed at :
- [promethues-meta](%s/prometheus-meta) - label **{"namespace" : "prombench-%d"}**
- [grafana](%s/grafana) - template-variable **"pr-number" : %d**

To cancel the benchmark process comment **/benchmark cancel** .`

		var resp string
		if benchmarkOption == "release" {
			resp = fmt.Sprintf(commentTemplate, fmt.Sprint("release-", releaseVersion), ingress_ip, number, ingress_ip, number)
			c.GitHubClient.CreateComment(org, repo, number, plugins.FormatICResponse(ic.Comment, resp))

			err := triggerBenchmarkJob(c, ic, startBenchmarkJobName, []string{cancelBenchmarkJobName}, "master", "quay.io/prometheus/prometheus:master", strings.Replace(releaseVersion, ".", "-", -1), fmt.Sprintf("quay.io/prometheus/prometheus:%s", releaseVersion))
			if err != nil {
				c.GitHubClient.CreateComment(org, repo, number, plugins.FormatICResponse(ic.Comment, fmt.Sprintf("Creation of prombench failed: %v", err)))
				return fmt.Errorf("Failed to create prowjob to start-benchmark %v.", err)
			}
		} else {
			resp = fmt.Sprintf(commentTemplate, fmt.Sprintf("pr-%d", number), ingress_ip, number, ingress_ip, number)
			c.GitHubClient.CreateComment(org, repo, number, plugins.FormatICResponse(ic.Comment, resp))

			err := startPRBenchmarkJob(c, ic)
			if err != nil {
				c.GitHubClient.CreateComment(org, repo, number, plugins.FormatICResponse(ic.Comment, fmt.Sprintf("Creation of prombench cluster failed: %v", err)))
				return fmt.Errorf("Failed to create prowjob to build-pr-image and start-benchmark %v.", err)
			}
		}
	} else {
		if !hasBenchmarkLabel {
			return c.GitHubClient.CreateComment(org, repo, number, plugins.FormatICResponse(ic.Comment, "Looks like benchmarking is not going on for this PR.<br/> You can start benchmarking by commenting `/benchmark [pr|release]` :smiley:"))
		}
		err := triggerBenchmarkJob(c, ic, cancelBenchmarkJobName, []string{buildPRJobName, startBenchmarkJobName}, "temp1", "temp1", "temp2", "temp2")
		if err != nil {
			c.GitHubClient.CreateComment(org, repo, number, plugins.FormatICResponse(ic.Comment, fmt.Sprintf("Deletion of prombench failed: %v", err)))
			return fmt.Errorf("Failed to create prowjob to stop-benchmark %v.", err)
		}
		c.Logger.Infof("Removing Benchmark label.")
		if err := c.GitHubClient.RemoveLabel(org, repo, number, benchmarkLabel); err != nil {
			return err
		}
	}
	return nil
}

func triggerBenchmarkJob(c client, ic github.IssueCommentEvent, jobName string, otherJobNames []string, prometheus1Name string, prometheus1Image string, prometheus2Name string, prometheus2Image string) error {

	err := waitForOtherBenchmarkJobToEnd(c, ic, otherJobNames, jobName)
	if err != nil {
		return err
	}
	c.Logger.Infof("All pending %s jobs have finished", jobName)

	org := ic.Repo.Owner.Login
	repo := ic.Repo.Name
	number := ic.Issue.Number

	pr, err := c.GitHubClient.GetPullRequest(org, repo, number)
	if err != nil {
		return err
	}

	baseSHA, err := c.GitHubClient.GetRef(org, repo, "heads/"+pr.Base.Ref)
	if err != nil {
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
		if job.Name == jobName {
			c.Logger.Debugf("Adding env variables to %s prowjob", jobName)

			// Add environment variables telling which version to benchmark
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
	c.Logger.WithFields(pjutil.ProwJobFields(&pj)).Info("Creating a new prowjob to ", jobName)
	if _, err := c.KubeClient.CreateProwJob(pj); err != nil {
		fmt.Errorf("Failed to Create %s ProwJob %v.", jobName, err)
		return err
	}
	return nil
}

func startPRBenchmarkJob(c client, ic github.IssueCommentEvent) error {

	err := waitForOtherBenchmarkJobToEnd(c, ic, []string{cancelBenchmarkJobName}, buildPRJobName)
	if err != nil {
		return err
	}
	c.Logger.Infof("All pending cancel-benchmark jobs have finished")

	org := ic.Repo.Owner.Login
	repo := ic.Repo.Name
	number := ic.Issue.Number

	pr, err := c.GitHubClient.GetPullRequest(org, repo, number)
	if err != nil {
		return err
	}

	baseSHA, err := c.GitHubClient.GetRef(org, repo, "heads/"+pr.Base.Ref)
	if err != nil {
		return err
	}

	var prBuilderJob, startBenchmarkJob config.Presubmit
	imageName := fmt.Sprintf("%s/prombench-pr-image:pr-%d", projectName, number)
	c.Logger.Infof("PR image name is %s", imageName)

	for _, job := range c.Config.Presubmits[pr.Base.Repo.FullName] {
		if job.Name == buildPRJobName {
			c.Logger.Debugf("Adding env variables to %s prowjob", buildPRJobName)

			job.Spec.Containers[0].Env = append(job.Spec.Containers[0].Env, kubeEnv(map[string]string{prowJobPRNumber: strconv.Itoa(number)})...)
			job.Spec.Containers[0].Env = append(job.Spec.Containers[0].Env, kubeEnv(map[string]string{"PROW_BENCHMARK_DOCKER_IMAGE": imageName})...)
			prBuilderJob = job
		}
		if job.Name == startBenchmarkJobName {
			c.Logger.Debugf("Adding env variables to %s prowjob", startBenchmarkJobName)

			// Add environment variables telling which version to benchmark
			job.Spec.Containers[0].Env = append(job.Spec.Containers[0].Env, kubeEnv(map[string]string{prowJobPRNumber: strconv.Itoa(number)})...)
			job.Spec.Containers[0].Env = append(job.Spec.Containers[0].Env, kubeEnv(map[string]string{prowJobPrometheus1Name: "master"})...)
			job.Spec.Containers[0].Env = append(job.Spec.Containers[0].Env, kubeEnv(map[string]string{prowJobPrometheus1Image: "quay.io/prometheus/prometheus:master"})...)
			job.Spec.Containers[0].Env = append(job.Spec.Containers[0].Env, kubeEnv(map[string]string{prowJobPrometheus2Name: fmt.Sprintf("pr-%d", number)})...)
			job.Spec.Containers[0].Env = append(job.Spec.Containers[0].Env, kubeEnv(map[string]string{prowJobPrometheus2Image: imageName})...)
			startBenchmarkJob = job
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

	labels := make(map[string]string)
	for k, v := range prBuilderJob.Labels {
		labels[k] = v
	}
	labels[github.EventGUID] = ic.GUID
	prBuilderPJ := pjutil.NewProwJob(pjutil.PresubmitSpec(prBuilderJob, kr), labels)

	labels = make(map[string]string)
	for k, v := range startBenchmarkJob.Labels {
		labels[k] = v
	}
	labels[github.EventGUID] = ic.GUID

	prBuilderPJ.Spec.RunAfterSuccess = append(prBuilderPJ.Spec.RunAfterSuccess, pjutil.PresubmitSpec(startBenchmarkJob, kr))

	c.Logger.WithFields(pjutil.ProwJobFields(&prBuilderPJ)).Info("Creating a new prowjob to build PR image and start benchmarking.")
	if _, err := c.KubeClient.CreateProwJob(prBuilderPJ); err != nil {
		fmt.Errorf("Failed to create build-PR-images -> start-benchmark ProwJob %v.", err)
		return err
	}
	return nil
}

func waitForOtherBenchmarkJobToEnd(c client, ic github.IssueCommentEvent, jobName []string, newJobName string) error {
	org := ic.Repo.Owner.Login
	repo := ic.Repo.Name
	number := ic.Issue.Number

	defer c.GitHubClient.RemoveLabel(org, repo, number, benchmarkPendingLabel) //remove label to not block future jobs

	for _, job := range jobName {

		pjs, err := c.KubeClient.ListProwJobs("")
		if err != nil {
			return err
		}

		pendingJobName := ""

	ProwJobLoop:
		for _, pj := range pjs {
			if pj.Status.State == kube.TriggeredState || pj.Status.State == kube.PendingState {
				if pj.Spec.Job == job {
					for _, e := range pj.Spec.PodSpec.Containers[0].Env {
						if e.Name == prowJobPRNumber && e.Value == strconv.Itoa(number) {
							c.Logger.Infof("Before starting %s, need to wait for %s Job.", newJobName, job)
							pendingJobName = pj.Name
							break ProwJobLoop
						}
					}
				}
			}
		}

		if pendingJobName != "" {

			c.GitHubClient.AddLabel(org, repo, number, benchmarkPendingLabel)
			c.GitHubClient.CreateComment(org, repo, number, plugins.FormatICResponse(ic.Comment, fmt.Sprintf("Looks like %s job is already running on this PR. Will start %s job once ongoing job is completed", job, newJobName)))
			var i int

			c.Logger.Debugf("Starting wait for job %s:%s", job, pendingJobName)
			for i = 0; i < maxTries; i++ {
				pj, err := c.KubeClient.GetProwJob(pendingJobName)

				if err != nil {
					return fmt.Errorf("Failed to get ProwJob %s to end %s.", pendingJobName, job)
				}

				if pj.Status.State == kube.TriggeredState || pj.Status.State == kube.PendingState {
					c.Logger.Debugf("%d: %s is ongoing. Retrying after 30 seconds.", i, job)
					retry := time.Second * 30
					time.Sleep(retry)
				} else {
					break
				}
			}
			if i >= maxTries {
				return fmt.Errorf("Ongoing %s job was not finished after trying for %d times.", job, maxTries)
			}
		}
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
