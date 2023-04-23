package exporter

import (
	"context"
	"fmt"
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

const (
	labelNameExprReverse = "expr_reversed"
	labelNameAlertState  = "alertstate"
	labelNameSeverity    = "severity"
	alertMetricName      = "ALERTS"
)

func (e *Exporter) fetchProbeStatus(clientApi promClientV1.API, ctx context.Context, promUrl string, rule promClientV1.AlertingRule) ([]string, error) {
	var results []string

	query := ""
	for name, value := range rule.Annotations {
		if name == labelNameExprReverse {
			query = fmt.Sprintf(
				"%s OR %s{%s=\"%s\"}",
				string(value),
				alertMetricName,
				promCommonModel.AlertNameLabel,
				rule.Name,
			)
		}
	}

	if query == "" {
		return results, nil
	}

	ts := time.Now()
	res, warning, err := clientApi.Query(ctx, query, ts, promClientV1.WithTimeout(5*time.Second))

	if err != nil {
		level.Error(e.Logger).Log("err", "An error occurred when query prometheus", err)
		return results, err
	}

	for _, warn := range warning {
		level.Warn(e.Logger).Log("warn", "An warning occurred when query prometheus", warn)
	}

	vector := res.(promCommonModel.Vector)
	for _, sample := range vector {
		metric := e.processProbeSample(rule, sample, promUrl, ctx, ts)
		results = append(results, metric)
	}

	return results, nil
}

func (e *Exporter) processProbeSample(rule promClientV1.AlertingRule, sample *promCommonModel.Sample,
	promUrl string, ctx context.Context, ts time.Time) string {
	// init labelSet
	labels := rule.Labels.Clone()
	labels[promCommonModel.AlertNameLabel] = promCommonModel.LabelValue(rule.Name)
	labels[promCommonModel.InstanceLabel] = sample.Metric[promCommonModel.InstanceLabel]
	delete(labels, labelNameSeverity)

	// set value status
	value := e.Config.ProbeStatus.StateMapping.Ok
	if sample.Metric[promCommonModel.MetricNameLabel] == alertMetricName {
		if sample.Metric[labelNameAlertState] == "pending" {
			value = e.Config.ProbeStatus.StateMapping.Pending
		} else if sample.Metric[labelNameSeverity] == "warning" {
			value = e.Config.ProbeStatus.StateMapping.Warning
		} else {
			value = e.Config.ProbeStatus.StateMapping.Firing
		}
	}
	labelsMap := make(map[string]string, len(sample.Metric))
	for name, val := range sample.Metric {
		labelsMap[string(name)] = string(val)
		if contains(e.Config.ProbeStatus.KeepLabels, string(name)) {
			labels[name] = val
		}
	}
	tmplData := promTemplate.AlertTemplateData(labelsMap, nil, promUrl, float64(sample.Value))
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
			"__probe_"+rule.Name,
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
			level.Warn(e.Logger).Log("msg", "Expanding alert prometheus failed", "err", errTmpl, "data", tmplData)
		}
		return result
	}

	for name, val := range labels {
		labels[name] = promCommonModel.LabelValue(expand(string(val)))
	}
	return fmt.Sprintf("probe_status%s %d", labels.String(), value)
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}
