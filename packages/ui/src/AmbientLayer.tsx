import { useEffect, useRef } from 'react'

interface Particle { x: number; y: number; r: number; vx: number; vy: number; hue: number; alpha: number; phase: number }

const DESKTOP_COUNT = 46
const MOBILE_COUNT = 18

/**
 * Fixed canvas of drifting light motes + a film-grain overlay, shared behind
 * every view. Also drives --mx/--my (viewport-relative pointer position) which
 * positions the single background pointer-light in `.ambient-scene`. The light
 * lives in the fixed background layer only — content components stay flat.
 */
export function AmbientLayer() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    const ctx = canvas?.getContext('2d')
    if (!canvas || !ctx) return

    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    const isMobile = window.matchMedia('(max-width: 720px)').matches
    const count = isMobile ? MOBILE_COUNT : DESKTOP_COUNT

    let width = 0
    let height = 0
    let raf = 0
    let hidden = false

    const spawn = (): Particle => ({
      x: Math.random() * width,
      y: Math.random() * height,
      r: Math.random() * 1.6 + .6,
      vx: (Math.random() - .5) * .06,
      vy: -Math.random() * .08 - .02,
      hue: Math.random() > .5 ? 214 : 165,
      alpha: Math.random() * .35 + .15,
      phase: Math.random() * Math.PI * 2,
    })
    let particles: Particle[] = []

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2)
      width = window.innerWidth
      height = window.innerHeight
      canvas.width = width * dpr
      canvas.height = height * dpr
      canvas.style.width = `${width}px`
      canvas.style.height = `${height}px`
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      if (particles.length === 0) particles = Array.from({ length: count }, spawn)
    }
    resize()

    const paint = (list: Particle[], flickerFor: (particle: Particle) => number) => {
      ctx.clearRect(0, 0, width, height)
      for (const particle of list) {
        const flicker = flickerFor(particle)
        const glowR = particle.r * 6
        const gradient = ctx.createRadialGradient(particle.x, particle.y, 0, particle.x, particle.y, glowR)
        gradient.addColorStop(0, `hsla(${particle.hue}, 90%, 78%, ${particle.alpha * flicker})`)
        gradient.addColorStop(1, 'hsla(0, 0%, 0%, 0)')
        ctx.fillStyle = gradient
        ctx.beginPath()
        ctx.arc(particle.x, particle.y, glowR, 0, Math.PI * 2)
        ctx.fill()
      }
    }

    const onPointerMove = (event: PointerEvent) => {
      document.documentElement.style.setProperty('--mx', `${(event.clientX / window.innerWidth * 100).toFixed(2)}%`)
      document.documentElement.style.setProperty('--my', `${(event.clientY / window.innerHeight * 100).toFixed(2)}%`)
    }
    const onVisibility = () => { hidden = document.hidden }

    window.addEventListener('resize', resize)
    document.addEventListener('visibilitychange', onVisibility)
    if (!reduceMotion) window.addEventListener('pointermove', onPointerMove, { passive: true })

    if (reduceMotion) {
      paint(particles, () => .6)
    } else {
      const draw = () => {
        raf = requestAnimationFrame(draw)
        if (hidden) return
        for (const particle of particles) {
          particle.x += particle.vx
          particle.y += particle.vy
          particle.phase += .004
          if (particle.y < -20) { particle.y = height + 10; particle.x = Math.random() * width }
          if (particle.x < -20) particle.x = width + 10
          if (particle.x > width + 20) particle.x = -10
        }
        paint(particles, (particle) => .75 + Math.sin(particle.phase) * .25)
      }
      raf = requestAnimationFrame(draw)
    }

    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('resize', resize)
      window.removeEventListener('pointermove', onPointerMove)
      document.removeEventListener('visibilitychange', onVisibility)
    }
  }, [])

  return (
    <>
      <canvas ref={canvasRef} className="particle-field" aria-hidden="true" />
      <div className="grain-overlay" aria-hidden="true" />
    </>
  )
}
