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
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
	// "github.com/prometheus/benchmark"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/test-infra/prow/git"
	"k8s.io/test-infra/prow/github"
	"k8s.io/test-infra/prow/pluginhelp"
	"k8s.io/test-infra/prow/plugins"
	"k8s.io/test-infra/prow/repoowners"
)

const pluginName = "benchmark"
const repoName = "prometheus/prometheus"

var (
	benchmarkLabel           = "benchmark"
	benchmarkRe              = regexp.MustCompile(`(?mi)^/benchmark\s+(release|pr)\s*$`)
	benchmarkCancelRe        = regexp.MustCompile(`(?mi)^/benchmark\s+cancel\s*$`)
	removeBenchmarkLabelNoti = "New changes are detected. Benchmarking will be stopped."
	benchmarkReleaseNoti     = "Starting benchmarking current master with previous release. Status can be seen at http://COMING-SOON"
	benchmarkPRNoti          = "Starting benchmarking PR with current master. Status can be seen at http://COMING-SOON"
)

func init() {
	plugins.RegisterGenericCommentHandler(pluginName, handleGenericComment, helpProvider)
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
	GetPullRequestChanges(org, repo string, number int) ([]github.PullRequestChange, error)
	ListIssueComments(org, repo string, number int) ([]github.IssueComment, error)
	DeleteComment(org, repo string, ID int) error
	BotName() (string, error)
}

func handleGenericComment(pc plugins.PluginClient, e github.GenericCommentEvent) error {
	return handle(pc.GitHubClient, pc.GitClient, pc.PluginConfig, pc.OwnersClient, pc.Logger, &e)
}

func handle(ghc githubClient, gc *git.Client, config *plugins.Configuration, ownersClient repoowners.Interface, log *logrus.Entry, e *github.GenericCommentEvent) error {
	// Only consider open PRs and new comments.

	if !e.IsPR || e.IssueState != "open" || e.Action != github.GenericCommentActionCreated {
		return nil
	}

	// If we create an "/benchmark" comment, add benchmark if necessary.
	// If we create a "/benchmark cancel" comment, remove benchmark if necessary.
	// wantBenchmark := false
	// if benchmarkRe.MatchString(e.Body) {
	// 	wantBenchmark = true
	// } else if benchmarkCancelRe.MatchString(e.Body) {
	// 	wantBenchmark = false
	// } else {
	// 	return nil
	// }
	benchmarkOption := "pr"
	if strings.Contains(e.Body, "release") {
		benchmarkOption = "release"
	}

	buildPrometheusImages(gc, benchmarkOption, log)

	/*	org := e.Repo.Owner.Login
		repo := e.Repo.Name
		commentAuthor := e.User.Login

		ro, err := loadRepoOwners(ghc, ownersClient, org, repo, e.Number)
		if err != nil {
			return err
		}
		if !loadReviewers(ro, []string{"OWNERS"}).Has(commentAuthor) {
			resp := "adding benchmark is restricted to approvers in OWNERS files."
			log.Infof("Reply to /benchmark request with comment: \"%s\"", resp)
			return ghc.CreateComment(org, repo, e.Number, plugins.FormatResponseRaw(e.Body, e.HTMLURL, commentAuthor, resp))
		}

		// Only add the label if it doesn't have it, and vice versa.
		hasBenchmarkLabel := false
		labels, err := ghc.GetIssueLabels(org, repo, e.Number)
		if err != nil {
			log.WithError(err).Errorf("Failed to get the labels on %s/%s#%d.", org, repo, e.Number)
		}
		for _, candidate := range labels {
			if candidate.Name == benchmarkLabel {
				hasBenchmarkLabel = true
				break
			}
		}
		if hasBenchmarkLabel && !wantBenchmark {
			log.Infof("Removing Benchmark label.")
			return ghc.RemoveLabel(org, repo, e.Number, benchmarkLabel)
		} else if !hasBenchmarkLabel && wantBenchmark {
			resp := benchmarkPRNoti
			if benchmarkOption == "release" {
				resp = benchmarkReleaseNoti
			}
			buildPrometheusImages(gc, log)
			log.Infof("Adding Benchmark label.")
			if err := ghc.AddLabel(org, repo, e.Number, benchmarkLabel); err != nil {
				return err
			}
			// Delete the benchmark removed noti after the benchmark label is added.
			botname, err := ghc.BotName()
			if err != nil {
				log.WithError(err).Errorf("Failed to get bot name.")
			}
			comments, err := ghc.ListIssueComments(org, repo, e.Number)
			if err != nil {
				log.WithError(err).Errorf("Failed to get the list of issue comments on %s/%s#%d.", org, repo, e.Number)
			}
			for _, comment := range comments {
				if comment.User.Login == botname && (strings.Contains(comment.Body, removeBenchmarkLabelNoti) || strings.Contains(comment.Body, benchmarkReleaseNoti) || strings.Contains(comment.Body, benchmarkPRNoti)) {
					if err := ghc.DeleteComment(org, repo, comment.ID); err != nil {
						log.WithError(err).Errorf("Failed to delete comment from %s/%s#%d, ID:%d.", org, repo, e.Number, comment.ID)
					}
				}
			}
			ghc.CreateComment(org, repo, e.Number, plugins.FormatResponseRaw(e.Body, e.HTMLURL, commentAuthor, resp))
		}*/
	return nil
}

func buildPrometheusImages(gc *git.Client, benchmarkOption string, log *logrus.Entry) error {
	// building prometheus master
	r, err := gc.Clone(repoName)
	if err != nil {
		log.WithError(err).Error("Error cloning repo's master branch.")
		return err
	}
	log.Infof("Cloned successfully")

	defer func() {
		if err := r.Clean(); err != nil {
			log.WithError(err).Error("Error cleaning up repo's master branch.")
		}
	}()
	files, err := ioutil.ReadDir("./tmp/")
	if err != nil {
		log.WithError(err).Errorf("Failed to read directory.")
		return err
	}
	log.Infof("Read directory successfully")
	for _, f := range files {
		log.Infof("%s-FILE ::: %s", benchmarkOption, f.Name())
	}
	return nil
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
