// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

export interface TableColumn<T> {
  key: string
  label: string
  align?: 'left' | 'right' | 'center'
  /** CSS width (e.g. '120px', '18%') */
  width?: string
  /** When set, clicking the header sorts by this column */
  sortValue?: (row: T) => string | number | undefined
  /** Show the cell in a monospaced font */
  mono?: boolean
  /** Hide the column below this width */
  hideBelow?: 'sm' | 'md' | 'lg'
}
