import { describe, expect, it } from 'vitest'
import { safeHref } from './safeHref'
import { parseFindingSearch } from './findingSearch'
import { reportFilename } from '@/api/reports'

describe('safeHref', () => {
  it('allows http and https only', () => {
    expect(safeHref('https://www.example.org/a')).toBe('https://www.example.org/a')
    expect(safeHref('http://x.example:80/')).toBe('http://x.example/')
    expect(safeHref('javascript:alert(1)')).toBeNull()
    expect(safeHref('data:text/html,<b>x</b>')).toBeNull()
    expect(safeHref('not a url')).toBeNull()
  })
})

describe('parseFindingSearch', () => {
  it('keeps known filters and drops the rest', () => {
    expect(parseFindingSearch({ scan_id: 'abc', severity: 'low', evil: 'x', page: '2' })).toEqual({
      scan_id: 'abc',
      severity: 'low',
      page: 2,
    })
  })
})

describe('reportFilename', () => {
  it('uses the real extension instead of .bin', () => {
    expect(reportFilename({ id: '12345678abc', report_type: 'pentest' })).toBe('netra-pentest-12345678.pdf')
    expect(reportFilename({ id: '12345678abc', report_type: 'technical', file_path: '/r/technical_x.docx' })).toBe(
      'netra-technical-12345678.docx',
    )
  })
})
