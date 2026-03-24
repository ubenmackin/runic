import { useRef, useState, useMemo, useEffect } from 'react'
import { processHourlyData, drawChart } from '../utils/chart'

export default function BlockedEventsChart({ logs }) {
  const canvasRef = useRef(null)
  const [hoveredBar, setHoveredBar] = useState(null)

  const hourlyData = useMemo(() => processHourlyData(logs), [logs])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    const { width, height } = canvas.getBoundingClientRect()
    const dpr = window.devicePixelRatio || 1

    canvas.width = width * dpr
    canvas.height = height * dpr
    ctx.scale(dpr, dpr)

    drawChart(ctx, width, height, hourlyData, hoveredBar)
  }, [hourlyData, hoveredBar])

  const maxValue = Math.max(...hourlyData.map(d => d.count), 1)
  const barWidth = 100 / hourlyData.length

  return (
    <div className="space-y-2">
      <div className="relative w-full h-32">
        <canvas
          ref={canvasRef}
          className="w-full h-full"
          onMouseLeave={() => setHoveredBar(null)}
        />
        {hourlyData.map((d, i) => (
          <div
            key={i}
            className="absolute bottom-0 h-full cursor-pointer"
            style={{
              left: `${i * barWidth}%`,
              width: `${barWidth}%`,
            }}
            onMouseEnter={() => setHoveredBar(i)}
          />
        ))}
      </div>
      {/* X-axis labels */}
      <div className="flex text-xs text-gray-400">
        {hourlyData.filter((_, i) => i % 4 === 0).map((d, i) => (
          <div key={i} className="flex-1 text-center">
            {d.label}
          </div>
        ))}
      </div>
      {/* Tooltip */}
      {hoveredBar !== null && hourlyData[hoveredBar] && (
        <div className="absolute bg-gray-900 text-white text-xs px-2 py-1 rounded shadow-lg">
          {hourlyData[hoveredBar].label}: {hourlyData[hoveredBar].count} blocked
        </div>
      )}
    </div>
  )
}
