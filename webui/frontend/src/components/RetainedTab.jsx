import { useRef } from 'react'

// Mount on first visit and preserve the last rendered view while hidden.
export default function RetainedTab({ active, children, ...props }) {
  const retained = useRef(null)
  const visited = useRef(false)
  if (active) {
    visited.current = true
    retained.current = children
  }
  if (!visited.current) return null
  return <div {...props} hidden={!active} style={{ display: active ? undefined : 'none' }}>{retained.current}</div>
}
