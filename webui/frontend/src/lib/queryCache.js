// A scan workspace owns this cache. No background expiry or global user data.
export function createQueryCache() {
  let entries = new Map()
  return {
    clear() { entries = new Map() },
    peek(key) { return entries.get(key)?.value },
    get(key, load) {
      if (entries.has(key)) return entries.get(key).request
      const current = entries
      const entry = {}
      const request = Promise.resolve().then(load).then(value => { entry.value = value; return value }).catch(error => {
        if (current.get(key) === entry) current.delete(key)
        throw error
      })
      entry.request = request
      current.set(key, entry)
      return request
    },
  }
}

export function queryKey(options) {
  return JSON.stringify(Object.entries(options).sort(([a], [b]) => a.localeCompare(b)))
}
