package clashapi

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
)

// 面板整组测速超时后，没跑完的成员必须丢掉旧延时，否则面板会把上一次的数字
// 当成这次测出来的结果。
func TestDropHistoryForSkippedMembers(t *testing.T) {
	history := urltest.NewHistoryStorage()
	store := func(tag string, delay uint16) {
		history.StoreURLTestHistory(tag, &adapter.URLTestHistory{Time: time.Now(), Delay: delay})
	}
	store("家宽/cn-xin1", 88)
	store("家宽/🇨🇳 上海", 106)
	store("快乐鸡/🇭🇰 Hk01-优选1", 152)
	store("不在组里/别动", 44)

	members := []string{"家宽/cn-xin1", "家宽/🇨🇳 上海", "快乐鸡/🇭🇰 Hk01-优选1", "从没测过"}
	result := map[string]uint16{"家宽/🇨🇳 上海": 106}

	dropHistoryForSkippedMembers(history, members, result)

	if history.LoadURLTestHistory("家宽/🇨🇳 上海") == nil {
		t.Fatal("测出结果的成员不该被清")
	}
	for _, tag := range []string{"家宽/cn-xin1", "快乐鸡/🇭🇰 Hk01-优选1"} {
		if history.LoadURLTestHistory(tag) != nil {
			t.Fatalf("被跳过的成员 %s 应清空历史", tag)
		}
	}
	if history.LoadURLTestHistory("不在组里/别动") == nil {
		t.Fatal("不属于该组的节点不该被波及")
	}
}

func TestDropHistoryForSkippedMembersNilHistory(t *testing.T) {
	// 没有历史存储时(比如未启用 cache_file)不能 panic
	dropHistoryForSkippedMembers(nil, []string{"a"}, map[string]uint16{})
}
