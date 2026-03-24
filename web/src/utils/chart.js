export function processHourlyData(logs) {
  const now = new Date()
  const buckets = []

  // Create 24 hourly buckets
  for (let i = 23; i >= 0; i--) {
    const hourStart = new Date(now.getTime() - i * 60 * 60 * 1000)
    buckets.push({
      hour: hourStart.getHours(),
      label: hourStart.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      count: 0,
    })
  }

  // Count logs in each bucket
  logs?.forEach(log => {
    const logDate = new Date(log.timestamp)
    const hoursAgo = Math.floor((now - logDate) / (60 * 60 * 1000))
    if (hoursAgo >= 0 && hoursAgo < 24) {
      const bucketIndex = 23 - hoursAgo
      if (buckets[bucketIndex]) {
        buckets[bucketIndex].count++
      }
    }
  })

  return buckets
}

export function drawChart(ctx, width, height, data, hoveredBar) {
  const padding = { top: 10, right: 10, bottom: 5, left: 30 }
  const chartWidth = width - padding.left - padding.right
  const chartHeight = height - padding.top - padding.bottom

  const maxValue = Math.max(...data.map(d => d.count), 1)
  const barWidth = chartWidth / data.length
  const barPadding = 2

  // Clear canvas
  ctx.clearRect(0, 0, width, height)

  // Draw Y-axis labels
  ctx.fillStyle = '#9ca3af'
  ctx.font = '10px sans-serif'
  ctx.textAlign = 'right'
  ctx.fillText(maxValue.toString(), padding.left - 5, padding.top + 10)
  ctx.fillText('0', padding.left - 5, height - padding.bottom)

  // Draw grid lines
  ctx.strokeStyle = '#e5e7eb'
  ctx.lineWidth = 0.5
  for (let i = 0; i <= 4; i++) {
    const y = padding.top + (chartHeight * i) / 4
    ctx.beginPath()
    ctx.moveTo(padding.left, y)
    ctx.lineTo(width - padding.right, y)
    ctx.stroke()
  }

  // Draw bars
  data.forEach((d, i) => {
    const barHeight = (d.count / maxValue) * chartHeight
    const x = padding.left + i * barWidth + barPadding
    const y = padding.top + chartHeight - barHeight
    const w = barWidth - barPadding * 2

    const isHovered = hoveredBar === i
    ctx.fillStyle = isHovered ? '#dc2626' : '#ef4444'
    ctx.fillRect(x, y, w, barHeight)

    // Draw bar top line for visibility when count is low
    if (d.count > 0 && barHeight < 2) {
      ctx.fillRect(x, y, w, 2)
    }
  })
}
