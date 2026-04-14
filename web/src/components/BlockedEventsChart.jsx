import { useRef, useState, useMemo, useEffect, useCallback } from 'react'
import { processHourlyData, drawChart } from '../utils/chart'

export default function BlockedEventsChart({ logs }) {
  const canvasRef = useRef(null)
  const containerRef = useRef(null)
  const [hoveredPoint, setHoveredPoint] = useState(null)
  const [tooltipPosition, setTooltipPosition] = useState({ top: 0, left: 0 })

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

    drawChart(ctx, width, height, hourlyData, hoveredPoint)
  }, [hourlyData, hoveredPoint])

  const segmentWidth = 100 / hourlyData.length

  const handlePointHover = useCallback((index, _event) => {
    if (!containerRef.current) return

    const container = containerRef.current
    const containerRect = container.getBoundingClientRect()
    const tooltipWidth = 150 // estimated tooltip width
    const tooltipHeight = 32 // estimated tooltip height
    const padding = 8

    // Calculate segment position within the container
    const segmentLeftPercent = index * segmentWidth
    const segmentWidthPercent = segmentWidth
    const segmentCenterPercent = segmentLeftPercent + (segmentWidthPercent / 2)
    const segmentCenterPx = (segmentCenterPercent / 100) * containerRect.width

    // Calculate tooltip position
    let left = segmentCenterPx - (tooltipWidth / 2)
    let top = -tooltipHeight - padding // Position above the chart

    // Keep tooltip within container bounds
    if (left < 0) left = 0
    if (left + tooltipWidth > containerRect.width) {
      left = containerRect.width - tooltipWidth
    }

    setTooltipPosition({ top, left })
    setHoveredPoint(index)
  }, [segmentWidth])

  const handleMouseLeave = useCallback(() => {
    setHoveredPoint(null)
  }, [])

  return (
    <div className="space-y-2">
      <div
        ref={containerRef}
        className="relative w-full h-32"
        onMouseLeave={handleMouseLeave}
      >
        <canvas
          ref={canvasRef}
          className="w-full h-full"
        />
        {hourlyData.map((d, i) => (
          <div
            key={i}
            className="absolute bottom-0 h-full cursor-pointer"
            style={{
              left: `${i * segmentWidth}%`,
              width: `${segmentWidth}%`,
            }}
            onMouseEnter={(e) => handlePointHover(i, e)}
          />
        ))}
        {/* Tooltip */}
        {hoveredPoint !== null && hourlyData[hoveredPoint] && (
          <div
            className="absolute bg-gray-900 text-white text-xs px-2 py-1 rounded-none shadow-none pointer-events-none"
            style={{
              top: `${tooltipPosition.top}px`,
              left: `${tooltipPosition.left}px`,
              transform: 'translateX(50%)',
              whiteSpace: 'nowrap',
              zIndex: 10,
            }}
          >
            {hourlyData[hoveredPoint].label}: {hourlyData[hoveredPoint].count} blocked
          </div>
        )}
      </div>
      {/* X-axis labels */}
      <div className="flex text-xs text-gray-400">
        {hourlyData.filter((_, i) => i % 4 === 0).map((d, i) => (
          <div key={i} className="flex-1 text-center">
            {d.label}
          </div>
        ))}
      </div>
    </div>
  )
}
