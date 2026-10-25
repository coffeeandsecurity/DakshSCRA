const COLORS = {
  red: '#f85149', green: '#3fb950', blue: '#58a6ff', cyan: '#39c5cf',
  yellow: '#d29922', orange: '#e3842a', purple: '#a371f7', magenta: '#db61a2',
}

export function HighlightedSource({ code = '', highlights = [] }) {
  const chars = Array.from(String(code))
  const spans = (Array.isArray(highlights) ? highlights.slice(0, 256) : []).filter(span =>
    span && Number.isInteger(span.start) && Number.isInteger(span.end) &&
    span.start >= 0 && span.end > span.start && span.end <= chars.length,
  )
  if (!spans.length) return code
  const cuts = [...new Set([0, chars.length, ...spans.flatMap(span => [span.start, span.end])])].sort((a, b) => a - b)
  return cuts.slice(0, -1).map((start, index) => {
    const end = cuts[index + 1]
    const text = chars.slice(start, end).join('')
    const span = spans.find(item => item.start <= start && item.end >= end)
    return span ? <mark className="pattern-source-mark" data-color={span.color}
      style={{ '--pattern-mark-color': COLORS[span.color] || (/^#[0-9a-f]{6}$/i.test(span.color) ? span.color : COLORS.red) }} key={start}>{text}</mark> : text
  })
}

export function GuidanceText({ text = '' }) {
  const normalized = String(text).replace(/—/g, '. ').replace(/;/g, '.')
    .replace(/(?<!\d)\s+(\d+\.\s+)(?=[A-Z])/g, '\n$1')
    .replace(/(checks|review|steps|actions|verify):\s*(?=\n?\d+\.\s)/gi, '$1:\n')
  const blocks = []
  let list = [], paragraph = []
  function flush() {
    if (paragraph.length) { blocks.push({ text: paragraph.join(' ') }); paragraph = [] }
    if (list.length) { blocks.push({ items: list }); list = [] }
  }
  for (const raw of normalized.split('\n')) {
    const line = raw.trim(), match = line.match(/^\d+[.)]\s+(.+)/)
    if (match) { if (paragraph.length) flush(); list.push(match[1]) }
    else if (!line) flush()
    else { if (list.length) flush(); paragraph.push(line) }
  }
  flush()
  return <div className="pattern-guidance">{blocks.map((block, index) => block.items
    ? <ol key={index}>{block.items.map((item, step) => <li key={step}>{item}</li>)}</ol>
    : <p key={index}>{block.text}</p>)}</div>
}
