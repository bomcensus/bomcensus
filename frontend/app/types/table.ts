export interface TableColumn<T> {
  key: string
  label: string
  align?: 'left' | 'right' | 'center'
  /** CSS 너비 (예: '120px', '18%') */
  width?: string
  /** 지정하면 헤더를 눌러 정렬할 수 있다 */
  sortValue?: (row: T) => string | number | undefined
  /** 셀을 고정폭 글꼴로 표시 */
  mono?: boolean
  /** 이 폭 미만에서는 열을 숨긴다 */
  hideBelow?: 'sm' | 'md' | 'lg'
}
