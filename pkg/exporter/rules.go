package exporter

import (
	"context"
	"fmt"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	promClientV1 "github.com/prometheus/client_golang/api/prometheus/v1"
	promCommonModel "github.com/prometheus/common/model"
	promTimestamp "github.com/prometheus/prometheus/model/timestamp"
	promTemplate "github.com/prometheus/prometheus/template"
	"net/url"

	"github.com/prometheus/prometheus/promql"
	"strings"
	"time"
)

const labelNameExprReverse = "expr_reversed"
const labelNameAlertState = "alertstate"

func fetchProbeOk(logger log.Logger, clientApi promClientV1.API, ctx context.Context, promUrl string, rule promClientV1.AlertingRule) ([]string, error) {
	var results []string

	query := ""
	for name, value := range rule.Annotations {
		if name == labelNameExprReverse {
			query = string(value)
		}
	}

	if query == "" {
		return results, nil
	}

	ts := time.Now()
	res, warning, err := clientApi.Query(ctx, query, ts, promClientV1.WithTimeout(5*time.Second))

	if err != nil {
		level.Error(logger).Log("err", "An error occurred when query prometheus", err)
		return results, err
	}

	for _, warn := range warning {
		level.Warn(logger).Log("warn", "An warning occurred when query prometheus", warn)
	}

	vector := res.(promCommonModel.Vector)
	for _, sample := range vector {
		labels := rule.Labels
		labels[promCommonModel.AlertNameLabel] = promCommonModel.LabelValue(rule.Name)
		labels[labelNameAlertState] = "ok"
		labels[promCommonModel.InstanceLabel] = sample.Metric[promCommonModel.InstanceLabel]

		labelsMap := make(map[string]string, len(sample.Metric))
		for name, value := range sample.Metric {
			labelsMap[string(name)] = string(value)
		}
		tmplData := promTemplate.AlertTemplateData(labelsMap, nil, promUrl, 0)
		// Inject some convenience variables that are easier to remember for users
		// who are not used to Go's templating system.
		defs := []string{
			"{{$labels := .Labels}}",
			"{{$externalLabels := .ExternalLabels}}",
			"{{$externalURL := .ExternalURL}}",
			"{{$value := .Value}}",
		}
		externalUrl, _ := url.Parse(promUrl)
		expand := func(text string) string {
			tmpl := promTemplate.NewTemplateExpander(
				ctx,
				strings.Join(append(defs, text), ""),
				"__alert_"+rule.Name,
				tmplData,
				promCommonModel.Time(promTimestamp.FromTime(ts)),
				promTemplate.QueryFunc(func(context.Context, string, time.Time) (promql.Vector, error) {
					return nil, nil
				}),
				externalUrl,
				nil,
			)
			result, errTmpl := tmpl.Expand()
			if errTmpl != nil {
				result = fmt.Sprintf("<error expanding promTemplate: %s>", errTmpl)
				level.Warn(logger).Log("msg", "Expanding alert prometheus failed", "err", errTmpl, "data", tmplData)
			}
			return result
		}

		//labels[promCommonModel.LabelName("title")] = promCommonModel.LabelValue(expand("{{ $labels.instance }} of job {{ $labels.job }} {{ $labels.region }}"))
		for name, value := range labels {
			labels[name] = promCommonModel.LabelValue(expand(string(value)))
		}
		results = append(results, fmt.Sprintf("ALERTS%s %d", labels.String(), 1))
	}

	return results, nil
}
