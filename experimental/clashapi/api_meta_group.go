package clashapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badjson"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func groupRouter(server *Server) http.Handler {
	r := chi.NewRouter()
	r.Get("/", getGroups(server))
	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProxyName, findProxyByName(server))
		r.Get("/", getGroup(server))
		r.Get("/delay", getGroupDelay(server))
	})
	return r
}

func getGroups(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		groups := common.Map(common.Filter(server.outbound.Outbounds(), func(it adapter.Outbound) bool {
			_, isGroup := it.(adapter.OutboundGroup)
			return isGroup
		}), func(it adapter.Outbound) *badjson.JSONObject {
			return proxyInfo(server, it)
		})
		render.JSON(w, r, render.M{
			"proxies": groups,
		})
	}
}

func getGroup(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
		if _, ok := proxy.(adapter.OutboundGroup); ok {
			render.JSON(w, r, proxyInfo(server, proxy))
			return
		}
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, ErrNotFound)
	}
}

func getGroupDelay(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		proxy := r.Context().Value(CtxKeyProxy).(adapter.Outbound)
		outboundGroup, ok := proxy.(adapter.OutboundGroup)
		if !ok {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}

		query := r.URL.Query()
		url := query.Get("url")
		if strings.HasPrefix(url, "http://") {
			url = ""
		}
		timeout, err := strconv.ParseInt(query.Get("timeout"), 10, 32)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), time.Millisecond*time.Duration(timeout))
		defer cancel()

		var result map[string]uint16
		if urlTestGroup, isURLTestGroup := outboundGroup.(adapter.URLTestGroup); isURLTestGroup {
			result, err = urlTestGroup.URLTest(ctx)
		} else if loadBalanceGroup, isLoadBalanceGroup := outboundGroup.(adapter.LoadBalanceGroup); isLoadBalanceGroup {
			result, err = loadBalanceGroup.URLTest(ctx)
		} else {
			outbounds := common.FilterNotNil(common.Map(outboundGroup.All(), func(it string) adapter.Outbound {
				itOutbound, _ := server.outbound.Outbound(it)
				return itOutbound
			}))
			result = group.URLTestOutbounds(ctx, server.outbound, server.urlTestHistory, server.logger, outbounds, url, 0, true)
		}

		// 整组测速受调用方 timeout 约束(面板固定发 5000ms)，超时后没跑完的成员
		// 会留着上一次的延时，面板就把旧数字当成了这次的结果。只有真的被 timeout
		// 截断时才清空这些成员，让它们显示为无数据(黑)；锁竞争那种"一个探测都
		// 没发出去"的空结果不清，否则会把整组误判成黑。
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			dropHistoryForSkippedMembers(server.urlTestHistory, collectDelayTags(server, outboundGroup), result)
		}

		if err != nil && len(result) == 0 {
			render.Status(r, http.StatusGatewayTimeout)
			render.JSON(w, r, newError(err.Error()))
			return
		}

		render.JSON(w, r, result)
	}
}

// collectDelayTags 递归展开组，返回这次测速会触及的全部 tag。
// 组的成员常常是另一个组(例如 国内出口 -> 国内免流 -> 一堆节点)，
// 只取 All() 会漏掉嵌套里的叶子节点，那些节点被跳过后仍然留着旧延时。
func collectDelayTags(server *Server, outboundGroup adapter.OutboundGroup) []string {
	var tags []string
	visited := make(map[string]bool)
	var walk func(current adapter.OutboundGroup)
	walk = func(current adapter.OutboundGroup) {
		for _, tag := range current.All() {
			if visited[tag] {
				continue
			}
			visited[tag] = true
			tags = append(tags, tag)
			if member, _ := server.outbound.Outbound(tag); member != nil {
				if nested, isGroup := member.(adapter.OutboundGroup); isGroup {
					walk(nested)
				}
			}
		}
	}
	walk(outboundGroup)
	return tags
}

// dropHistoryForSkippedMembers 删除本次测速没有返回结果的成员的历史延时。
// result 里没有的成员，要么探测失败，要么在 timeout 之前没轮到/没跑完，
// 两种情况下都不该继续展示旧值。
func dropHistoryForSkippedMembers(history *urltest.HistoryStorage, members []string, result map[string]uint16) {
	if history == nil {
		return
	}
	for _, memberTag := range members {
		if _, tested := result[memberTag]; tested {
			continue
		}
		history.DeleteURLTestHistory(memberTag)
	}
}
