// Where the reader was on a route when they left it, so Back from the console returns the landing story to the same
// beat instead of restarting it (ui-ux-pro-max quick-reference §9 back-behavior, state-preservation).
const saved: Record<string, number> = {}

export const rememberScroll = (route: string) => { saved[route] = window.scrollY }

export function takeScroll(route: string): number {
  const y = saved[route] ?? 0
  delete saved[route]
  return y
}
