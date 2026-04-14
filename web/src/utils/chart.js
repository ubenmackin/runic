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
  const stepWidth = chartWidth / data.length

  // Clear canvas
  ctx.clearRect(0, 0, width, height)

  // Draw Y-axis labels
  ctx.fillStyle = '#9ca3af'
  ctx.font = '10px sans-serif'
  ctx.textAlign = 'right'
  ctx.fillText(maxValue.toString(), padding.left - 5, padding.top + 10)
  ctx.fillText('0', padding.left - 5, height - padding.bottom)

  // Draw grid lines (sharp, no rounded corners)
  ctx.strokeStyle = '#e5e7eb'
  ctx.lineWidth = 0.5
  for (let i = 0; i <= 4; i++) {
    const y = padding.top + (chartHeight * i) / 4
    ctx.beginPath()
    ctx.moveTo(padding.left, y)
    ctx.lineTo(width - padding.right, y)
    ctx.stroke()
  }

  // Build stepped line path (curveStepAfter interpolation)
  // For each point: horizontal line to next x, then vertical line to next y
  ctx.beginPath()
  
  const firstX = padding.left
  const firstY = padding.top + chartHeight - (data[0].count / maxValue) * chartHeight
  
  ctx.moveTo(firstX, firstY)
  
  for (let i = 0; i < data.length; i++) {
    const _currentX = padding.left + i * stepWidth
    const currentY = padding.top + chartHeight - (data[i].count / maxValue) * chartHeight
    const nextX = padding.left + (i + 1) * stepWidth
    
    // Horizontal line to next x position (step after - hold value until next point)
    ctx.lineTo(nextX, currentY)
    
    // Vertical line to next point's y (at the next x)
    if (i < data.length - 1) {
      const nextY = padding.top + chartHeight - (data[i + 1].count / maxValue) * chartHeight
      ctx.lineTo(nextX, nextY)
    }
  }

  // Draw fill below the stepped line with low opacity
  ctx.lineTo(padding.left + chartWidth, padding.top + chartHeight)
  ctx.lineTo(padding.left, padding.top + chartHeight)
  ctx.closePath()
  
  ctx.fillStyle = 'rgba(239, 68, 68, 0.15)' // red-500 with low opacity
  ctx.fill()

  // Draw the stepped line on top
  ctx.beginPath()
  ctx.moveTo(firstX, firstY)
  
  for (let i = 0; i < data.length; i++) {
    const currentY = padding.top + chartHeight - (data[i].count / maxValue) * chartHeight
    const nextX = padding.left + (i + 1) * stepWidth
    
    ctx.lineTo(nextX, currentY)
    
    if (i < data.length - 1) {
      const nextY = padding.top + chartHeight - (data[i + 1].count / maxValue) * chartHeight
      ctx.lineTo(nextX, nextY)
    }
  }

  // Line color: red-500
  ctx.strokeStyle = hoveredBar !== null ? '#dc2626' : '#ef4444'
  ctx.lineWidth = 2
  ctx.lineJoin = 'miter' // Sharp corners
  ctx.stroke()

  // Draw hover indicator if a point is hovered
  if (hoveredBar !== null && data[hoveredBar]) {
    const hoverX = padding.left + hoveredBar * stepWidth + stepWidth / 2
    const hoverY = padding.top + chartHeight - (data[hoveredBar].count / maxValue) * chartHeight
    
    // Draw a small circle at the hovered point
    ctx.beginPath()
    ctx.arc(hoverX, hoverY, 4, 0, Math.PI * 2)
    ctx.fillStyle = '#dc2626'
    ctx.fill()
    ctx.strokeStyle = '#fff'
    ctx.lineWidth = 1.5
    ctx.stroke()
  }
}
