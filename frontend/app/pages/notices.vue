<!--
  Copyright (C) 2026 JC-Lab
  SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
  Additional terms apply. See LICENSING.md.
-->

<script setup lang="ts">
import type { NoticeMatch } from '~/types'
import type { TableColumn } from '~/types/table'
import { ExternalLink } from '@lucide/vue'
import { getNotice, getNoticeSummary, listNotices, markNoticesRead, markNoticesUnread, toApiError, type QueryOf } from '~/api'

useHead({ title: '보안 공지 · bomcensus' })

// Security notices (KISA, vendors) whose software is installed on an asset. The feed matches by product name
// only, not by version: the administrator reads the notice and decides whether it applies. Read notices are hidden.

const route = useRoute()
const router = useRouter()
const selected = computed(() => (typeof route.query.id === 'string' ? route.query.id : ''))

function go(id: string) {
  router.replace({ query: { ...route.query, id: id || undefined } })
}

// ── Filters ───────────────────────────────────────────

const q = ref('')
const source = ref('')
const showRead = ref(false)
// 'rank' is the server's order (unread first, then the newest) and stays out of the query.
const sort = ref('rank')
const sortOptions = [
  { value: 'rank', label: '안 읽은 것, 최신순' },
  { value: '-published', label: '공지일 최신순' },
  { value: 'published', label: '공지일 오래된 순' },
  { value: '-assets', label: '자산 많은 순' },
  { value: '-lastMatched', label: '최근 일치순' },
  { value: 'title', label: '제목순' },
]
const qDebounced = ref('')
let qTimer: ReturnType<typeof setTimeout> | undefined
watch(q, (v) => {
  clearTimeout(qTimer)
  qTimer = setTimeout(() => (qDebounced.value = v.trim()), 300)
})

// Paging of the list. Any other change starts over from the first page.
const page = ref(0)
const size = ref(50)
const conditions = computed(() => ({
  q: qDebounced.value || undefined,
  source: source.value || undefined,
  includeRead: showRead.value ? true : undefined,
  sort: sort.value === 'rank' ? undefined : (sort.value as QueryOf<typeof listNotices>['sort']),
}))
watch([() => JSON.stringify(conditions.value), size], () => (page.value = 0))
const filters = computed(() => ({ ...conditions.value, limit: size.value, offset: page.value * size.value }))
const sourceOptions = Object.entries(noticeSourceLabel).map(([value, label]) => ({ value, label }))

const { data: summary, refresh: refreshSummary } = useLoad('notices:summary', getNoticeSummary)
const { data: list, pending, error, refresh: refreshList } = useLoad(
  () => `notices:${JSON.stringify(filters.value)}`,
  () => listNotices(filters.value),
)

const current = computed(() => selected.value || list.value?.items[0]?.noticeId || '')
const { data: detail, error: detailError, refresh: refreshDetail } = useLoad(
  () => `notice:${current.value}`,
  () => (current.value ? getNotice(current.value) : Promise.resolve(undefined)),
)

// ── Read state ────────────────────────────────────────

// Selection is per page: ids that are not on the loaded page are dropped.
const checked = ref<string[]>([])
watch(list, (l) => {
  const ids = new Set(l?.items.map((n) => n.noticeId))
  checked.value = checked.value.filter((id) => ids.has(id))
  // Marking read can empty the last page; go back to the page that is now last.
  if (l && !l.items.length && page.value > 0) page.value = Math.max(0, Math.ceil(l.total / size.value) - 1)
})
const allChecked = computed(() => !!list.value?.items.length && checked.value.length === list.value.items.length)
function toggleAll() {
  checked.value = allChecked.value ? [] : (list.value?.items.map((n) => n.noticeId) ?? [])
}

const busy = ref(false)
const markError = ref('')
async function mark(ids: string[], read: boolean) {
  if (!ids.length) return
  busy.value = true
  markError.value = ''
  try {
    await (read ? markNoticesRead(ids) : markNoticesUnread(ids))
    checked.value = []
    await Promise.all([refreshSummary(), refreshList(), refreshDetail()])
  } catch (e) {
    markError.value = toApiError(e).message
  } finally {
    busy.value = false
  }
}

// ── Detail ────────────────────────────────────────────

const matchColumns: TableColumn<NoticeMatch>[] = [
  { key: 'asset', label: '자산', sortValue: (m) => m.assetName },
  { key: 'component', label: '컴포넌트', sortValue: (m) => `${m.componentName} ${m.componentVersion}` },
  { key: 'place', label: '위치', sortValue: (m) => matchPlace(m), hideBelow: 'md' },
  { key: 'firstSeen', label: '발견', align: 'right', sortValue: (m) => m.firstSeen, hideBelow: 'sm' },
]
const matchedAssets = computed(() => new Set(detail.value?.matches.map((m) => m.assetId)).size)
</script>

<template>
  <div>
    <PageHeader title="보안 공지">
      <template #subtitle>
        KISA·제조사 보안 공지 중 설치된 소프트웨어와 제품명이 일치하는 것입니다. 버전은 비교하지 않으니 적용 여부를 확인하세요.
      </template>
    </PageHeader>
    <p v-if="markError" class="note note-danger mb-3" role="alert">{{ markError }}</p>

    <FilterBar :count="list?.total" unit="개">
      <SearchInput v-model="q" placeholder="제목, 제품, CVE" />
      <SelectFilter v-model="source" label="출처" :options="sourceOptions" />
      <label class="inline-flex items-center gap-1.5 text-sm">
        <input v-model="showRead" type="checkbox" class="size-[15px] accent-(--accent)" /> 읽은 공지 포함
        <span v-if="summary" class="mono text-xs text-ink-3">{{ summary.total - summary.unread }}</span>
      </label>
      <label class="inline-flex items-center">
        <span class="sr-only">정렬</span>
        <select v-model="sort" class="select max-w-44" :class="sort !== 'rank' ? 'border-accent text-accent' : ''">
          <option v-for="o in sortOptions" :key="o.value" :value="o.value">정렬: {{ o.label }}</option>
        </select>
      </label>
      <template v-if="checked.length">
        <AppButton size="sm" :disabled="busy" @click="mark(checked, true)">읽음으로 표시 ({{ checked.length }})</AppButton>
        <AppButton v-if="showRead" size="sm" variant="ghost" :disabled="busy" @click="mark(checked, false)">안 읽음으로 표시</AppButton>
      </template>
    </FilterBar>

    <div class="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,24rem)_minmax(0,1fr)]">
      <!-- List -->
      <Panel flush class="min-w-0 self-start">
        <LoadError v-if="error" :error="error" @retry="refreshList" />
        <LoadingText v-else-if="pending && !list" class="p-3.5" />
        <p v-else-if="!list?.items.length" class="px-3.5 py-3 text-sm text-ink-2">
          {{ showRead ? '설치된 소프트웨어와 일치하는 공지가 없습니다.' : '읽지 않은 공지가 없습니다.' }}
        </p>
        <template v-else>
          <label class="flex items-center gap-2 border-b border-line px-3.5 py-1.5 text-xs text-ink-3">
            <input type="checkbox" class="size-[14px] accent-(--accent)" :checked="allChecked" @change="toggleAll" /> 모두 선택
          </label>
          <ul class="max-h-[70vh] overflow-y-auto">
            <li v-for="n in list.items" :key="n.noticeId" class="flex border-b border-line" :class="n.noticeId === current ? 'bg-accent-soft' : ''">
              <label class="flex shrink-0 items-start pl-3.5 pt-3">
                <span class="sr-only">{{ n.title }} 선택</span>
                <input v-model="checked" type="checkbox" :value="n.noticeId" class="size-[14px] accent-(--accent)" />
              </label>
              <button
                type="button"
                class="block min-w-0 flex-1 px-2.5 py-2.5 text-left hover:bg-surface-2"
                :aria-current="n.noticeId === current ? 'true' : undefined"
                @click="go(n.noticeId)"
              >
                <span class="flex items-center gap-1.5">
                  <span v-if="n.unread" class="size-1.5 shrink-0 rounded-full bg-accent" aria-label="읽지 않음" />
                  <span class="text-xs text-ink-3">{{ noticeSource(n.source) }}</span>
                  <StatusBadge v-if="n.unread && n.readAt" tone="warn" label="새 자산" />
                  <span class="ml-auto whitespace-nowrap text-xs text-ink-3">{{ formatDate(n.published) }}</span>
                </span>
                <span class="mt-0.5 line-clamp-2 block text-sm" :class="n.unread ? 'font-medium' : 'text-ink-2'" :title="n.title">{{ n.title }}</span>
                <span class="mt-1 block truncate text-xs text-ink-3">
                  자산 {{ n.assets }}<template v-if="n.software.length"> · {{ n.software.map((s) => s.product).join(', ') }}</template>
                </span>
              </button>
            </li>
          </ul>
        </template>
        <TablePager v-if="list && (list.total > size || page > 0)" v-model:page="page" v-model:size="size" :total="list.total" compact />
      </Panel>

      <!-- Detail -->
      <div class="min-w-0">
        <Panel v-if="detailError"><LoadError :error="detailError" @retry="refreshDetail" /></Panel>
        <Panel v-else-if="!current"><p class="text-sm text-ink-2">왼쪽에서 공지를 고르세요.</p></Panel>
        <Panel v-else-if="!detail || detail.notice.noticeId !== current"><LoadingText /></Panel>
        <div v-else class="grid grid-cols-1 gap-4">
          <Panel>
            <div class="flex flex-wrap items-center gap-2">
              <StatusBadge tone="info" :label="noticeSource(detail.notice.source)" />
              <StatusBadge v-if="detail.notice.unread" tone="warn" label="읽지 않음" dot />
              <StatusBadge v-else tone="neutral" label="읽음" />
              <span class="mono text-xs text-ink-3">{{ detail.notice.noticeId }}</span>
              <span class="ml-auto flex gap-2">
                <AppButton v-if="detail.notice.unread" size="sm" :disabled="busy" @click="mark([detail.notice.noticeId], true)">읽음으로 표시</AppButton>
                <AppButton v-if="detail.notice.readAt" size="sm" variant="ghost" :disabled="busy" @click="mark([detail.notice.noticeId], false)">
                  안 읽음으로 표시
                </AppButton>
              </span>
            </div>
            <h2 class="mt-2 text-lg font-semibold">{{ detail.notice.title }}</h2>
            <a
              v-if="noticeLink(detail.notice)"
              :href="noticeLink(detail.notice)"
              target="_blank"
              rel="noopener noreferrer"
              class="link mt-1 inline-flex items-center gap-1 text-sm"
            >원문 보기 <ExternalLink :size="13" aria-hidden="true" /></a>
            <p v-if="reopenedReason(detail.notice)" class="note note-warn mt-3">{{ reopenedReason(detail.notice) }}</p>
            <p v-if="detail.notice.summary" class="mt-3 max-w-[90ch] text-sm text-ink-2" lang="en">{{ detail.notice.summary }}</p>
            <dl class="kv mt-3">
              <dt>공개</dt>
              <dd>{{ formatDate(detail.notice.published) }}</dd>
              <template v-if="detail.notice.cveIds.length">
                <dt>CVE</dt>
                <dd class="mono text-xs">{{ detail.notice.cveIds.join(', ') }}</dd>
              </template>
              <template v-if="detail.notice.advisoryIds.length">
                <dt>기타 식별자</dt>
                <dd class="mono text-xs">{{ detail.notice.advisoryIds.join(', ') }}</dd>
              </template>
              <template v-if="detail.notice.readAt">
                <dt>읽음 표시</dt>
                <dd>{{ formatDateTime(detail.notice.readAt) }}<template v-if="detail.notice.readBy"> · {{ detail.notice.readBy }}</template></dd>
              </template>
              <template v-if="detail.notice.updated">
                <dt>갱신</dt>
                <dd>{{ formatDateTime(detail.notice.updated) }}</dd>
              </template>
            </dl>
          </Panel>

          <Panel title="소프트웨어" description="공지에 적힌 영향 버전과 수정 버전입니다. 설치된 버전과 비교하지 않았습니다." flush>
            <table class="w-full border-collapse text-sm">
              <thead>
                <tr class="border-b border-line text-left text-xs text-ink-3">
                  <th class="py-2 pl-3.5 font-normal">제품</th>
                  <th class="px-3 py-2 font-normal">영향 버전</th>
                  <th class="px-3 py-2 font-normal">수정 버전</th>
                  <th class="hidden py-2 pl-3 pr-3.5 font-normal md:table-cell">CPE</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(s, i) in detail.notice.software" :key="i" class="border-b border-line align-top last:border-b-0">
                  <td class="py-2 pl-3.5">
                    <span class="font-medium">{{ s.product }}</span>
                    <span v-if="s.vendor" class="ml-1 text-xs text-ink-2">{{ s.vendor }}</span>
                  </td>
                  <td class="px-3 py-2 text-xs">{{ s.affected || '—' }}</td>
                  <td class="px-3 py-2 text-xs">{{ s.fixed || '—' }}</td>
                  <td class="mono hidden py-2 pl-3 pr-3.5 text-xs text-ink-2 md:table-cell">{{ s.cpeVendor }}:{{ s.cpeProduct }}</td>
                </tr>
              </tbody>
            </table>
          </Panel>

          <Panel title="설치된 자산" :description="`자산 ${matchedAssets}곳 · 새 자산 ${detail.notice.newAssets}곳`" flush>
            <DataTable
              :columns="matchColumns"
              :rows="detail.matches"
              :row-key="(m) => `${m.assetId}/${m.container ?? ''}/${m.componentId}`"
              :page-size="50"
              empty="일치하는 자산이 없습니다"
            >
              <template #cell-asset="{ row }">
                <NuxtLink :to="`/assets/${row.assetId}?tab=notices`" class="font-medium hover:underline">{{ row.assetName }}</NuxtLink>
                <StatusBadge v-if="row.new && detail.notice.readAt" class="ml-1" tone="warn" label="새로 발견" />
                <div class="text-xs text-ink-3">{{ assetKindLabel[row.assetKind] }}</div>
              </template>
              <template #cell-component="{ row }">
                <NuxtLink :to="`/components/${row.componentId}`" class="hover:underline">{{ row.componentName }}</NuxtLink>
                <span class="mono ml-1 text-xs text-ink-2">{{ row.componentVersion }}</span>
              </template>
              <template #cell-place="{ row }">
                <span class="mono break-all text-xs text-ink-2" :title="row.locations.join('\n')">{{ matchPlace(row) }}</span>
              </template>
              <template #cell-firstSeen="{ row }"><span class="whitespace-nowrap text-xs">{{ formatDate(row.firstSeen) }}</span></template>
            </DataTable>
          </Panel>
        </div>
      </div>
    </div>
  </div>
</template>
