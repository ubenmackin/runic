import { useState, useRef, useEffect, useCallback, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, QUERY_KEYS } from '../api/client'
import SearchableSelect from '../components/SearchableSelect'
import { RotateCcw, X, Maximize2, ChevronRight, ChevronLeft, Minus, Plus } from 'lucide-react'
import * as d3 from 'd3'

// ──────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────

const COLORS = {
  forward:    '#22c55e',
  backward:   '#3b82f6',
  peerOnline: '#a855f7',
  peerOffline:'#6b7280',
  group:      '#f59e0b',
  startPeer:  '#a855f7',
  membership: '#6b728050',
}

const DARK_COLORS = {
  bg:         '#1a1a2e',
  nodeFill:   '#2d2d4e',
  nodeStroke: '#4a4a6e',
  text:       '#e2e8f0',
  textMuted:  '#94a3b8',
}

const LIGHT_COLORS = {
  bg:         '#f8fafc',
  nodeFill:   '#ffffff',
  nodeStroke: '#d1d5db',
  text:       '#1f2937',
  textMuted:  '#6b7280',
}

const FIRST_TIER_SPACING = 380
const MEMBER_SPACING = 280
const SIBLING_SPACING = 110

// ──────────────────────────────────────────────────────
// Hook: resolve group members for all relevant groups
// ──────────────────────────────────────────────────────

function useGroupMembers(groupIds) {
  return useQuery({
    queryKey: ['topology-group-members', ...groupIds],
    queryFn: async () => {
      if (!groupIds.length) return {}
      const results = {}
      await Promise.all(
        groupIds.map(async (gid) => {
          try {
            const members = await api.get(`/groups/${gid}/members`)
            results[gid] = members || []
          } catch {
            results[gid] = []
          }
        })
      )
      return results
    },
    enabled: groupIds.length > 0,
    staleTime: 30000,
  })
}

// ──────────────────────────────────────────────────────
// Build layout data: centered with left/right split
// ──────────────────────────────────────────────────────

function buildLayoutData(startPeerId, peers, groups, policies, services, groupMembersMap, expandedGroups) {
  if (!startPeerId || !peers?.length || !policies?.length) return null

  const activePolicies = policies.filter(p => p.enabled && p.action === 'ACCEPT')

  // Find all groups the starting peer belongs to
  const myGroupIds = new Set()
  for (const [gid, members] of Object.entries(groupMembersMap || {})) {
    if (members.some(m => m.id === startPeerId)) {
      myGroupIds.add(Number(gid))
    }
  }

  // Find policies involving the starting peer
  const relevantPolicies = activePolicies.filter(p => {
    if (p.source_type === 'peer' && p.source_id === startPeerId) return true
    if (p.target_type === 'peer' && p.target_id === startPeerId) return true
    if (p.source_type === 'group' && myGroupIds.has(p.source_id)) return true
    if (p.target_type === 'group' && myGroupIds.has(p.target_id)) return true
    return false
  })

  if (!relevantPolicies.length) return null

  const startPeer = peers.find(p => p.id === startPeerId)
  if (!startPeer) return null

  // Group policies by the "other" entity
  const connectionMap = new Map()

  for (const pol of relevantPolicies) {
    const serviceName = services?.find(s => s.id === pol.service_id)?.name || 'Unknown'
    const servicePorts = services?.find(s => s.id === pol.service_id)?.ports || ''

    let otherType, otherId, isStartSource

    if (
      (pol.source_type === 'peer' && pol.source_id === startPeerId) ||
      (pol.source_type === 'group' && myGroupIds.has(pol.source_id))
    ) {
      otherType = pol.target_type
      otherId = pol.target_id
      isStartSource = true
    } else {
      otherType = pol.source_type
      otherId = pol.source_id
      isStartSource = false
    }

    if (otherType === 'special') continue
    if (otherType === 'peer' && otherId === startPeerId) continue

    const entityKey = `${otherType}-${otherId}`

    if (!connectionMap.has(entityKey)) {
      let nodeData
      if (otherType === 'peer') {
        const peer = peers.find(p => p.id === otherId)
        if (!peer) continue
        nodeData = { id: entityKey, type: 'peer', entityId: otherId, label: peer.hostname || peer.ip_address, data: peer }
      } else if (otherType === 'group') {
        const group = groups.find(g => g.id === otherId)
        if (!group) continue
        nodeData = { id: entityKey, type: 'group', entityId: otherId, label: group.name, data: group, peerCount: group.peer_count || 0 }
      }
      if (nodeData) connectionMap.set(entityKey, { node: nodeData, edges: [] })
    }

    const conn = connectionMap.get(entityKey)
    if (!conn) continue

    if (pol.direction === 'forward' || pol.direction === 'both') {
      conn.edges.push({
        id: `${pol.id}-fwd`, direction: isStartSource ? 'forward' : 'backward',
        policyId: pol.id, policyName: pol.name, serviceName, servicePorts,
      })
    }
    if (pol.direction === 'backward' || pol.direction === 'both') {
      conn.edges.push({
        id: `${pol.id}-bwd`, direction: isStartSource ? 'backward' : 'forward',
        policyId: pol.id, policyName: pol.name, serviceName, servicePorts,
      })
    }
  }

  // Build children array with optional expanded group members
  const children = []
  for (const [, conn] of connectionMap) {
    const child = { ...conn.node, edges: conn.edges, members: [] }

    if (child.type === 'group' && expandedGroups.has(child.entityId)) {
      const members = groupMembersMap?.[child.entityId] || []
      child.expanded = true
      for (const member of members) {
        if (member.id === startPeerId) continue
        // Look up the full peer object for complete data (status, is_manual, etc.)
        const fullPeer = peers.find(p => p.id === member.id) || member
        child.members.push({
          id: `member-${child.entityId}-peer-${member.id}`,
          type: 'peer', entityId: member.id,
          label: fullPeer.hostname || fullPeer.ip_address,
          data: fullPeer, isMember: true,
        })
      }
    }

    children.push(child)
  }

  // Split children: first half left, second half right
  const half = Math.ceil(children.length / 2)
  const leftChildren = children.slice(0, half)
  const rightChildren = children.slice(half)

  return {
    root: {
      id: `peer-${startPeerId}`, type: 'peer', entityId: startPeerId,
      label: startPeer.hostname || startPeer.ip_address, data: startPeer, isStart: true,
    },
    leftChildren,
    rightChildren,
    totalConnections: children.length,
  }
}

// ──────────────────────────────────────────────────────
// Manually compute node positions for the dual-tree layout
// ──────────────────────────────────────────────────────

function computePositions(layoutData) {
  if (!layoutData) return { nodes: [], links: [] }

  const { root, leftChildren, rightChildren } = layoutData
  const nodes = []
  const links = []

  // Root in center
  const rootNode = { ...root, x: 0, y: 0 }
  nodes.push(rootNode)

  // Helper: position a side's children and their expanded members
  function positionSide(children, direction) {
    // direction: 1 = right, -1 = left
    const xOffset = direction * FIRST_TIER_SPACING

    // Count total slots needed (children + any expanded members)
    let totalSlots = 0
    const childSlotInfo = children.map(child => {
      const memberCount = child.members?.length || 0
      const slots = Math.max(1, memberCount) // at least 1 slot per child
      totalSlots += slots
      return { child, slots, memberCount }
    })

    // Slight spacing between children
    const totalHeight = totalSlots * SIBLING_SPACING
    let currentY = -totalHeight / 2 + SIBLING_SPACING / 2

    for (const { child, slots, memberCount } of childSlotInfo) {
      // Center the child within its slot range
      const childCenterY = currentY + ((slots - 1) * SIBLING_SPACING) / 2
      const childNode = { ...child, x: xOffset, y: childCenterY, side: direction }
      nodes.push(childNode)
      links.push({ source: rootNode, target: childNode, edges: child.edges, isMembership: false })

      // Position members at next level
      if (memberCount > 0) {
        const memberXOffset = direction * (FIRST_TIER_SPACING + MEMBER_SPACING)
        let memberY = currentY
        for (const member of child.members) {
          const memberNode = { ...member, x: memberXOffset, y: memberY, side: direction }
          nodes.push(memberNode)
          links.push({ source: childNode, target: memberNode, edges: [], isMembership: true })
          memberY += SIBLING_SPACING
        }
      }

      currentY += slots * SIBLING_SPACING
    }
  }

  positionSide(leftChildren, -1)
  positionSide(rightChildren, 1)

  return { nodes, links }
}

// ──────────────────────────────────────────────────────
// Tree Graph Renderer (centered dual-tree)
// ──────────────────────────────────────────────────────

function TreeGraph({ layoutData, isDark, onNodeClick, onEdgeClick, onGroupClick, onBackgroundClick }) {
  const svgRef = useRef(null)
  const containerRef = useRef(null)
  const zoomRef = useRef(null)
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 })

  const colors = isDark ? DARK_COLORS : LIGHT_COLORS

  useEffect(() => {
    const container = containerRef.current
    if (!container) return
    const ro = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect
      if (width > 0 && height > 0) setDimensions({ width, height })
    })
    ro.observe(container)
    return () => ro.disconnect()
  }, [])

  // Compute positions
  const { nodes, links } = useMemo(() => computePositions(layoutData), [layoutData])

  useEffect(() => {
    if (!svgRef.current || !nodes.length) return

    const svg = d3.select(svgRef.current)
    const { width, height } = dimensions

    svg.selectAll('*').remove()

    // Background click handler to close detail panel
    svg.on('click', () => onBackgroundClick?.())

    const defs = svg.append('defs')
    const glow = defs.append('filter').attr('id', 'glow').attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%')
    glow.append('feGaussianBlur').attr('stdDeviation', '6').attr('result', 'blur')
    glow.append('feMerge').selectAll('feMergeNode')
      .data(['blur', 'SourceGraphic']).join('feMergeNode').attr('in', d => d)

    const g = svg.append('g').attr('class', 'graph-container')

    const zoom = d3.zoom()
      .scaleExtent([0.2, 4])
      .on('zoom', (event) => g.attr('transform', event.transform))
    svg.call(zoom)
    zoomRef.current = zoom

    // Offset to center the graph in the SVG
    const cx = width / 2
    const cy = height / 2

    // ── Draw links ──
    const linkGroup = g.append('g').attr('class', 'links')
    // Deferred pill data — pills will be rendered in a top layer after nodes
    const deferredPills = []

    for (const link of links) {
      const sx = link.source.x + cx
      const sy = link.source.y + cy
      const tx = link.target.x + cx
      const ty = link.target.y + cy

      if (link.isMembership) {
        // Dashed membership line
        const midX = (sx + tx) / 2
        linkGroup.append('path')
          .attr('d', `M${sx},${sy} C${midX},${sy} ${midX},${ty} ${tx},${ty}`)
          .attr('fill', 'none')
          .attr('stroke', COLORS.membership)
          .attr('stroke-width', 1.5)
          .attr('stroke-dasharray', '6 4')
        continue
      }

      const edges = link.edges || []
      const hasForward = edges.some(e => e.direction === 'forward')
      const hasBackward = edges.some(e => e.direction === 'backward')
      const forwardEdges = edges.filter(e => e.direction === 'forward')
      const backwardEdges = edges.filter(e => e.direction === 'backward')

      const drawEdge = (direction, edgeList, offset) => {
        const color = direction === 'forward' ? COLORS.forward : COLORS.backward
        const osy = sy + offset
        const oty = ty + offset
        const midX = (sx + tx) / 2

        const pathD = `M${sx},${osy} C${midX},${osy} ${midX},${oty} ${tx},${oty}`

        linkGroup.append('path')
          .attr('d', pathD)
          .attr('fill', 'none')
          .attr('stroke', color)
          .attr('stroke-width', 2.5)
          .attr('stroke-dasharray', '8 4')
          .attr('opacity', 0.85)
          .attr('class', `edge-${direction}`)

        // Hitbox
        linkGroup.append('path')
          .attr('d', pathD).attr('fill', 'none').attr('stroke', 'transparent').attr('stroke-width', 20)
          .style('cursor', 'pointer')
          .on('click', (event) => { event.stopPropagation(); onEdgeClick?.(edgeList) })

        // Arrow at 75%
        const t = 0.75
        const bezierX = (a, b, c, d, t) => (1-t)**3*a + 3*(1-t)**2*t*b + 3*(1-t)*t**2*c + t**3*d
        const ax = bezierX(sx, midX, midX, tx, t)
        const ay = bezierX(osy, osy, oty, oty, t)
        const ax2 = bezierX(sx, midX, midX, tx, t + 0.01)
        const ay2 = bezierX(osy, osy, oty, oty, t + 0.01)
        const angle = Math.atan2(ay2 - ay, ax2 - ax) * 180 / Math.PI
        const flip = direction === 'backward' ? 180 : 0

        linkGroup.append('polygon')
          .attr('points', '0,-5 10,0 0,5')
          .attr('fill', color).attr('opacity', 0.9)
          .attr('transform', `translate(${ax},${ay}) rotate(${angle + flip})`)

        // Service pills near the target node (~80% along edge)
        const pillT = 0.80
        const px = bezierX(sx, midX, midX, tx, pillT)
        const py = bezierX(osy, osy, oty, oty, pillT)

        // Collect pill data for deferred rendering (on top of nodes)
        const serviceNames = [...new Set(edgeList.map(e => e.serviceName))]
        const pillText = serviceNames.length === 1 ? serviceNames[0] : `+${serviceNames.length}`

        deferredPills.push({
          x: px,
          y: py,
          serviceName: pillText,
          color,
          edgeList,
        })
      }

      if (hasForward && hasBackward) {
        drawEdge('forward', forwardEdges, -10)
        drawEdge('backward', backwardEdges, 10)
      } else if (hasForward) {
        drawEdge('forward', forwardEdges, 0)
      } else if (hasBackward) {
        drawEdge('backward', backwardEdges, 0)
      }
    }

    // ── Draw nodes ──
    const nodeGroup = g.append('g').attr('class', 'nodes')

    const nodeElements = nodeGroup.selectAll('g.node')
      .data(nodes).join('g').attr('class', 'node')
      .attr('transform', d => `translate(${d.x + cx},${d.y + cy})`)
      .style('cursor', 'pointer')
      .on('click', (event, d) => {
        event.stopPropagation()
        if (d.type === 'group' && !d.isMember) {
          onGroupClick?.(d)
        } else {
          onNodeClick?.(d)
        }
      })

    nodeElements.each(function(d) {
      const el = d3.select(this)
      const isManual = d.data?.is_manual

      if (d.isStart) {
        el.append('rect')
          .attr('x', -50).attr('y', -30).attr('width', 100).attr('height', 60).attr('rx', 16)
          .attr('fill', COLORS.startPeer + '15').attr('stroke', COLORS.startPeer)
          .attr('stroke-width', 3).attr('filter', 'url(#glow)')

        el.append('rect')
          .attr('x', -44).attr('y', -24).attr('width', 88).attr('height', 48).attr('rx', 12)
          .attr('fill', isDark ? DARK_COLORS.nodeFill : LIGHT_COLORS.nodeFill)
          .attr('stroke', COLORS.startPeer).attr('stroke-width', 2)

        el.append('text')
          .text(d.label.length > 14 ? d.label.slice(0, 12) + '…' : d.label)
          .attr('text-anchor', 'middle').attr('dominant-baseline', 'central').attr('y', -2)
          .attr('fill', colors.text).attr('font-size', '14px').attr('font-weight', '700')
          .attr('font-family', 'Inter, system-ui, sans-serif')

        el.append('text')
          .text('★ START').attr('text-anchor', 'middle').attr('y', 14)
          .attr('fill', COLORS.startPeer).attr('font-size', '8px').attr('font-weight', '700')
          .attr('letter-spacing', '0.5px').attr('font-family', 'Inter, system-ui, sans-serif')

      } else if (d.type === 'group') {
        const size = 30
        const hexPoints = Array.from({ length: 6 }, (_, i) => {
          const angle = (Math.PI / 3) * i - Math.PI / 6
          return `${Math.cos(angle) * size},${Math.sin(angle) * size}`
        }).join(' ')

        el.append('polygon').attr('points', hexPoints)
          .attr('fill', d.expanded ? (isDark ? '#422f18' : '#fef0c7') : (isDark ? DARK_COLORS.nodeFill : LIGHT_COLORS.nodeFill))
          .attr('stroke', COLORS.group).attr('stroke-width', d.expanded ? 3 : 2.5)

        const badge = el.append('g').attr('transform', 'translate(18, -22)')
        badge.append('circle').attr('r', 9).attr('fill', COLORS.group)
        badge.append('text').text(d.peerCount || 0)
          .attr('text-anchor', 'middle').attr('dominant-baseline', 'central')
          .attr('fill', '#fff').attr('font-size', '9px').attr('font-weight', 'bold')
          .attr('font-family', 'Inter, system-ui, sans-serif')

        el.append('text')
          .text(d.label.length > 14 ? d.label.slice(0, 12) + '…' : d.label)
          .attr('text-anchor', 'middle').attr('y', 44).attr('fill', colors.text)
          .attr('font-size', '13px').attr('font-weight', '500').attr('font-family', 'Inter, system-ui, sans-serif')

        el.append('text')
          .text(d.expanded ? '▼ GROUP' : '▶ GROUP')
          .attr('text-anchor', 'middle').attr('y', 57).attr('fill', COLORS.group)
          .attr('font-size', '8px').attr('font-weight', '700').attr('letter-spacing', '0.5px')
          .attr('font-family', 'Inter, system-ui, sans-serif')

      } else {
        const isOnline = d.data?.status === 'online'
        const strokeColor = isManual ? '#8b5cf6' : (isOnline ? COLORS.peerOnline : COLORS.peerOffline)

        el.append('rect')
          .attr('x', -50).attr('y', -24).attr('width', 100).attr('height', 48).attr('rx', 10)
          .attr('fill', isDark ? DARK_COLORS.nodeFill : LIGHT_COLORS.nodeFill)
          .attr('stroke', strokeColor).attr('stroke-width', 2)

        if (!isManual) {
          el.append('circle')
            .attr('cx', 32).attr('cy', -16).attr('r', 5)
            .attr('fill', isOnline ? '#22c55e' : '#ef4444')
            .attr('stroke', isDark ? DARK_COLORS.nodeFill : LIGHT_COLORS.nodeFill).attr('stroke-width', 1.5)
        }

        el.append('text')
          .text(d.label.length > 14 ? d.label.slice(0, 12) + '…' : d.label)
          .attr('text-anchor', 'middle').attr('dominant-baseline', 'central')
          .attr('fill', colors.text).attr('font-size', '13px').attr('font-weight', '500')
          .attr('font-family', 'Inter, system-ui, sans-serif')

        if (d.isMember) {
          el.append('text').text('member')
            .attr('text-anchor', 'middle').attr('y', 34).attr('fill', colors.textMuted)
            .attr('font-size', '8px').attr('font-style', 'italic').attr('font-family', 'Inter, system-ui, sans-serif')
        }
      }
    })

    // ── Draw service pills on top of everything ──
    const pillLayer = g.append('g').attr('class', 'pills')
    for (const pill of deferredPills) {
      const pillG = pillLayer.append('g')
        .attr('transform', `translate(${pill.x}, ${pill.y})`)
        .style('cursor', 'pointer')
        .on('click', (event) => {
          event.stopPropagation()
          if (pill.edgeList) onEdgeClick?.(pill.edgeList)
        })

      const text = pillG.append('text')
        .text(pill.serviceName).attr('text-anchor', 'middle').attr('dominant-baseline', 'central')
        .attr('fill', pill.color).attr('font-size', '10px').attr('font-weight', '600')
        .attr('font-family', 'Inter, system-ui, sans-serif')

      const bbox = text.node().getBBox()
      const pw = bbox.width + 14, ph = 18

      pillG.insert('rect', 'text')
        .attr('x', -pw / 2).attr('y', -ph / 2).attr('width', pw).attr('height', ph)
        .attr('rx', 9).attr('ry', 9)
        .attr('fill', isDark ? '#2d2d4e' : '#ffffff')
        .attr('stroke', pill.color).attr('stroke-width', 1.5).attr('opacity', 0.95)
    }

    // ── Animate edges ──
    let animFrame, animTime = 0
    function animate() {
      animTime += 0.5
      g.selectAll('.edge-forward').attr('stroke-dashoffset', -animTime)
      g.selectAll('.edge-backward').attr('stroke-dashoffset', animTime)
      animFrame = requestAnimationFrame(animate)
    }
    animate()

    // ── Auto-fit ──
    setTimeout(() => {
      const bounds = g.node()?.getBBox()
      if (!bounds || bounds.width === 0) return
      const pad = 60
      const scale = Math.min(width / (bounds.width + pad * 2), height / (bounds.height + pad * 2), 1.2)
      const tx = width / 2 - (bounds.x + bounds.width / 2) * scale
      const ty = height / 2 - (bounds.y + bounds.height / 2) * scale
      svg.transition().duration(600)
        .call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale))
    }, 100)

    return () => cancelAnimationFrame(animFrame)
    // colors is derived from isDark, so only isDark needs to be in deps
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes, links, dimensions, isDark, onBackgroundClick, onNodeClick, onEdgeClick, onGroupClick])

  // Zoom controls
  const handleZoomIn = useCallback(() => {
    d3.select(svgRef.current).transition().duration(300).call(zoomRef.current.scaleBy, 1.3)
  }, [])
  const handleZoomOut = useCallback(() => {
    d3.select(svgRef.current).transition().duration(300).call(zoomRef.current.scaleBy, 0.7)
  }, [])
  const handleRecenter = useCallback(() => {
    const svg = d3.select(svgRef.current)
    const gEl = svg.select('g.graph-container')
    const bounds = gEl.node()?.getBBox()
    if (!bounds || bounds.width === 0) return
    const { width, height } = dimensions
    const pad = 60
    const scale = Math.min(width / (bounds.width + pad * 2), height / (bounds.height + pad * 2), 1.2)
    const tx = width / 2 - (bounds.x + bounds.width / 2) * scale
    const ty = height / 2 - (bounds.y + bounds.height / 2) * scale
    svg.transition().duration(500)
      .call(zoomRef.current.transform, d3.zoomIdentity.translate(tx, ty).scale(scale))
  }, [dimensions])

  return (
    <div ref={containerRef} className="relative w-full h-full" style={{ minHeight: '500px' }}>
      <svg ref={svgRef} width={dimensions.width} height={dimensions.height} style={{ background: colors.bg }} />
      {/* Zoom controls */}
<div className="absolute bottom-4 right-4 flex flex-col gap-1">
      <button onClick={handleZoomIn} className="p-2 rounded-none bg-white dark:bg-charcoal-dark border border-gray-200 dark:border-gray-border hover:bg-gray-50 dark:hover:bg-charcoal-darkest transition-colors" title="Zoom in">
          <Plus className="w-4 h-4 text-gray-700 dark:text-light-neutral" />
        </button>
        <button onClick={handleZoomOut} className="p-2 rounded-none bg-white dark:bg-charcoal-dark border border-gray-200 dark:border-gray-border hover:bg-gray-50 dark:hover:bg-charcoal-darkest transition-colors" title="Zoom out">
          <Minus className="w-4 h-4 text-gray-700 dark:text-light-neutral" />
        </button>
        <button onClick={handleRecenter} className="p-2 rounded-none bg-white dark:bg-charcoal-dark border border-gray-200 dark:border-gray-border hover:bg-gray-50 dark:hover:bg-charcoal-darkest transition-colors" title="Fit to view">
          <Maximize2 className="w-4 h-4 text-gray-700 dark:text-light-neutral" />
        </button>
      </div>
      {/* Legend */}
      <div className="absolute top-4 left-4 bg-white/90 dark:bg-charcoal-dark/90 backdrop-blur-sm rounded-none p-3 border border-gray-200 dark:border-gray-border text-xs space-y-2">
        <div className="font-semibold text-gray-700 dark:text-light-neutral mb-1">Legend</div>
        <div className="flex items-center gap-2">
          <span className="w-6 h-0.5 block" style={{ background: COLORS.forward }} />
          <span className="text-gray-600 dark:text-gray-400">Forward (Source → Target)</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-6 h-0.5 block" style={{ background: COLORS.backward }} />
          <span className="text-gray-600 dark:text-gray-400">Backward (Target → Source)</span>
        </div>
        <div className="flex items-center gap-2">
          <svg width="16" height="16" viewBox="0 0 16 16"><rect x="2" y="3" width="12" height="10" rx="3" fill="none" stroke={COLORS.peerOnline} strokeWidth="1.5" /></svg>
          <span className="text-gray-600 dark:text-gray-400">Peer</span>
        </div>
        <div className="flex items-center gap-2">
          <svg width="16" height="16" viewBox="0 0 16 16">
            <polygon points="8,1 14.5,5 14.5,11 8,15 1.5,11 1.5,5" fill="none" stroke={COLORS.group} strokeWidth="1.5" />
          </svg>
          <span className="text-gray-600 dark:text-gray-400">Group (click to toggle)</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-6 h-0.5 block border-t-2 border-dashed border-gray-400" />
          <span className="text-gray-600 dark:text-gray-400">Group membership</span>
        </div>
      </div>
    </div>
  )
}

// ──────────────────────────────────────────────────────
// Detail Panel
// ──────────────────────────────────────────────────────

function DetailPanel({ selection, onClose, onExpand, onCollapse }) {
  if (!selection) return null
  const { type, data } = selection

  return (
    <div className="absolute top-0 right-0 h-full w-80 bg-white dark:bg-charcoal-dark border-l border-gray-200 dark:border-gray-border shadow-none z-10 flex flex-col overflow-hidden animate-slide-in">
      <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-border flex items-center justify-between shrink-0">
        <h3 className="font-semibold text-gray-900 dark:text-light-neutral text-sm">
          {type === 'peer' ? 'Peer Details' : type === 'group' ? 'Group Details' : 'Connection Details'}
        </h3>
        <button onClick={onClose} className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded">
          <X className="w-4 h-4 text-gray-400" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {type === 'peer' && (
          <>
            <div>
              <div className="text-xs text-gray-500 dark:text-amber-muted uppercase tracking-wide mb-1">Hostname</div>
              <div className="text-sm font-medium text-gray-900 dark:text-light-neutral">{data.data?.hostname || '—'}</div>
            </div>
            <div>
              <div className="text-xs text-gray-500 dark:text-amber-muted uppercase tracking-wide mb-1">IP Address</div>
              <div className="text-sm font-mono text-gray-900 dark:text-light-neutral">{data.data?.ip_address || '—'}</div>
            </div>
            <div>
              <div className="text-xs text-gray-500 dark:text-amber-muted uppercase tracking-wide mb-1">Status</div>
              <div className="flex items-center gap-2">
                {data.data?.is_manual ? (
                  <>
                    <span className="w-2 h-2 rounded-full bg-violet-400 shadow-[0_0_8px_rgba(167,139,250,0.6)]" />
                    <span className="text-sm text-gray-900 dark:text-light-neutral">Manual</span>
                  </>
                ) : (
                  <>
                    <span className={`w-2 h-2 rounded-full ${data.data?.status === 'online' ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]' : 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.6)]'}`} />
                    <span className="text-sm text-gray-900 dark:text-light-neutral capitalize">{data.data?.status || 'unknown'}</span>
                  </>
                )}
              </div>
            </div>
            {data.data?.os_type && (
              <div>
                <div className="text-xs text-gray-500 dark:text-amber-muted uppercase tracking-wide mb-1">OS / Arch</div>
                <div className="text-sm text-gray-900 dark:text-light-neutral">{data.data.os_type} {data.data.arch ? `(${data.data.arch})` : ''}</div>
              </div>
            )}
            {data.data?.agent_version && (
              <div>
                <div className="text-xs text-gray-500 dark:text-amber-muted uppercase tracking-wide mb-1">Agent Version</div>
                <div className="text-sm font-mono text-gray-900 dark:text-light-neutral">{data.data.agent_version}</div>
              </div>
            )}
            {data.isStart && (
              <div className="mt-2 px-3 py-2 bg-purple-50 dark:bg-purple-active/10 rounded-none border border-purple-200 dark:border-purple-active/30">
                <span className="text-xs font-medium text-purple-700 dark:text-purple-400">★ Starting Peer</span>
              </div>
            )}
          </>
        )}

        {type === 'group' && (
          <>
            <div>
              <div className="text-xs text-gray-500 dark:text-amber-muted uppercase tracking-wide mb-1">Group Name</div>
              <div className="text-sm font-medium text-gray-900 dark:text-light-neutral">{data.label}</div>
            </div>
            <div>
              <div className="text-xs text-gray-500 dark:text-amber-muted uppercase tracking-wide mb-1">Members</div>
              <div className="text-sm text-gray-900 dark:text-light-neutral">{data.peerCount || 0} peers</div>
            </div>
            {data.expanded ? (
              <button
                onClick={() => onCollapse?.(data)}
                className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-gray-50 dark:bg-charcoal-darkest border border-gray-200 dark:border-gray-border hover:bg-gray-100 dark:hover:bg-charcoal-dark text-gray-700 dark:text-gray-300 text-sm font-medium rounded-none transition-colors"
              >
                <ChevronLeft className="w-4 h-4" />
                Collapse Group
              </button>
            ) : (
              <button
                onClick={() => onExpand?.(data)}
                className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 hover:bg-amber-100 dark:hover:bg-amber-500/20 text-amber-700 dark:text-amber-400 text-sm font-medium rounded-none transition-colors"
              >
                Expand Group
                <ChevronRight className="w-4 h-4" />
              </button>
            )}
          </>
        )}

        {type === 'edge' && (
          <div className="space-y-6">
            {(Array.isArray(data) ? data : [data]).map((edge, i) => (
              <div key={i} className="space-y-4 pb-6 border-b border-gray-100 dark:border-charcoal-darkest last:border-0 last:pb-0">
                <div>
                  <div className="text-xs text-gray-500 dark:text-amber-muted uppercase tracking-wide mb-1">Policy</div>
                  <div className="text-sm font-medium text-gray-900 dark:text-light-neutral">{edge.policyName}</div>
                </div>
                <div>
                  <div className="text-xs text-gray-500 dark:text-amber-muted uppercase tracking-wide mb-1">Direction</div>
                  <div className="flex items-center gap-2">
                    <span className="w-3 h-0.5 block" style={{ background: edge.direction === 'forward' ? COLORS.forward : COLORS.backward }} />
                    <span className="text-sm text-gray-900 dark:text-light-neutral capitalize">{edge.direction}</span>
                  </div>
                </div>
                <div>
                  <div className="text-xs text-gray-500 dark:text-amber-muted uppercase tracking-wide mb-1">Service</div>
                  <div className="text-sm text-gray-900 dark:text-light-neutral">{edge.serviceName}</div>
                </div>
                {edge.servicePorts && (
                  <div>
                    <div className="text-xs text-gray-500 dark:text-amber-muted uppercase tracking-wide mb-1">Ports</div>
                    <div className="flex flex-wrap gap-1.5">
                      {edge.servicePorts.split(',').map((p, j) => (
                        <span key={j} className="px-2 py-0.5 text-xs font-mono bg-gray-100 dark:bg-charcoal-darkest text-gray-700 dark:text-gray-300">{p.trim()}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ──────────────────────────────────────────────────────
// Main Topology Page
// ──────────────────────────────────────────────────────

export default function Topology() {
  const [selectedPeerId, setSelectedPeerId] = useState(null)
  const [expandedGroups, setExpandedGroups] = useState(new Set())
  const [detailSelection, setDetailSelection] = useState(null)

  const [isDark, setIsDark] = useState(() => document.documentElement.classList.contains('dark'))
  useEffect(() => {
    const observer = new MutationObserver(() => setIsDark(document.documentElement.classList.contains('dark')))
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
    return () => observer.disconnect()
  }, [])

  const { data: peers } = useQuery({ queryKey: QUERY_KEYS.peers(), queryFn: () => api.get('/peers') })
  const { data: groups } = useQuery({ queryKey: QUERY_KEYS.groups(), queryFn: () => api.get('/groups') })
  const { data: policies } = useQuery({ queryKey: QUERY_KEYS.policies(), queryFn: () => api.get('/policies') })
  const { data: services } = useQuery({ queryKey: QUERY_KEYS.services(), queryFn: () => api.get('/services') })

  const relevantGroupIds = useMemo(() => {
    if (!policies || !groups) return []
    const ids = new Set()
    policies.forEach(p => {
      if (p.enabled && p.action === 'ACCEPT') {
        if (p.source_type === 'group') ids.add(p.source_id)
        if (p.target_type === 'group') ids.add(p.target_id)
      }
    })
    return Array.from(ids)
  }, [policies, groups])

  const { data: groupMembersMap } = useGroupMembers(relevantGroupIds)

  const layoutData = useMemo(() =>
    buildLayoutData(selectedPeerId, peers, groups, policies, services, groupMembersMap, expandedGroups),
    [selectedPeerId, peers, groups, policies, services, groupMembersMap, expandedGroups]
  )

  const peerOptions = useMemo(() =>
    (peers || []).map(p => ({ value: p.id, label: p.hostname || p.ip_address })),
    [peers]
  )

  const handlePeerSelect = useCallback((id) => {
    setSelectedPeerId(id || null)
    setExpandedGroups(new Set())
    setDetailSelection(null)
  }, [])

  const handleReset = useCallback(() => {
    setSelectedPeerId(null)
    setExpandedGroups(new Set())
    setDetailSelection(null)
  }, [])

  const handleNodeClick = useCallback((node) => {
    setDetailSelection({ type: node.type, data: node })
  }, [])

  const handleEdgeClick = useCallback((edge) => {
    setDetailSelection({ type: 'edge', data: edge })
  }, [])

  const handleGroupClick = useCallback((groupNode) => {
    // Toggle expand/collapse on click
    setExpandedGroups(prev => {
      const next = new Set(prev)
      if (next.has(groupNode.entityId)) {
        next.delete(groupNode.entityId)
      } else {
        next.add(groupNode.entityId)
      }
      return next
    })
    // Just toggle — no detail panel for groups
  }, [])

  const handleExpand = useCallback((groupNode) => {
    setExpandedGroups(prev => {
      const next = new Set(prev)
      next.add(groupNode.entityId)
      return next
    })
    setDetailSelection(null)
  }, [])

  const handleCollapse = useCallback((groupNode) => {
    setExpandedGroups(prev => {
      const next = new Set(prev)
      next.delete(groupNode.entityId)
      return next
    })
    setDetailSelection(null)
  }, [])

  const handleBackgroundClick = useCallback(() => {
    setDetailSelection(null)
  }, [])

  return (
    <div className="space-y-4 h-[calc(100vh-52px-2rem)] md:h-[calc(100vh-52px-3rem)] flex flex-col overflow-hidden">
      <div className="flex items-center justify-between shrink-0">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-light-neutral">Topology</h1>
          <p className="text-gray-600 dark:text-amber-muted">Visualize network connections between peers and groups</p>
        </div>
        {selectedPeerId && (
          <button
            onClick={handleReset}
            className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-700 dark:text-amber-primary bg-white dark:bg-charcoal-dark border border-gray-300 dark:border-gray-border rounded-none hover:bg-gray-50 dark:hover:bg-charcoal-darkest"
          >
            <RotateCcw className="w-4 h-4" />
            Reset
          </button>
        )}
      </div>

      <div className="shrink-0 bg-white dark:bg-charcoal-dark rounded-none shadow-none p-4 border border-gray-200 dark:border-gray-border">
        <div className="flex items-center gap-4">
          <label className="text-sm font-medium text-gray-700 dark:text-amber-primary whitespace-nowrap">Starting Peer</label>
          <div className="w-72">
            <SearchableSelect options={peerOptions} value={selectedPeerId || ''} onChange={handlePeerSelect} placeholder="Select a peer to explore…" />
          </div>
          {selectedPeerId && !layoutData && (
            <span className="text-sm text-gray-500 dark:text-amber-muted italic">No enabled ACCEPT policies involve this peer.</span>
          )}
          {layoutData && (
            <span className="text-sm text-gray-500 dark:text-amber-muted">
              {layoutData.totalConnections} connections
              {expandedGroups.size > 0 && ` · ${expandedGroups.size} group${expandedGroups.size > 1 ? 's' : ''} expanded`}
            </span>
          )}
        </div>
      </div>

      <div className="flex-1 relative bg-white dark:bg-charcoal-dark rounded-none shadow-none border border-gray-200 dark:border-gray-border overflow-hidden" style={{ minHeight: '500px' }}>
        {!selectedPeerId ? (
          <div className="flex flex-col items-center justify-center h-full text-center p-8">
            <svg className="w-24 h-24 mb-6 text-gray-300 dark:text-gray-600" viewBox="0 0 100 100" fill="none">
              <rect x="10" y="35" rx="3" width="25" height="14" stroke="currentColor" strokeWidth="1.5" />
              <rect x="10" y="55" rx="3" width="25" height="14" stroke="currentColor" strokeWidth="1.5" />
              <circle cx="50" cy="50" r="10" stroke="currentColor" strokeWidth="2" />
              <rect x="65" y="35" rx="3" width="25" height="14" stroke="currentColor" strokeWidth="1.5" />
              <rect x="65" y="55" rx="3" width="25" height="14" stroke="currentColor" strokeWidth="1.5" />
              <line x1="35" y1="42" x2="40" y2="47" stroke="currentColor" strokeWidth="1.5" strokeDasharray="4 3" />
              <line x1="35" y1="62" x2="40" y2="53" stroke="currentColor" strokeWidth="1.5" strokeDasharray="4 3" />
              <line x1="60" y1="47" x2="65" y2="42" stroke="currentColor" strokeWidth="1.5" strokeDasharray="4 3" />
              <line x1="60" y1="53" x2="65" y2="62" stroke="currentColor" strokeWidth="1.5" strokeDasharray="4 3" />
            </svg>
            <h3 className="text-lg font-semibold text-gray-700 dark:text-light-neutral mb-2">Select a Starting Peer</h3>
            <p className="text-sm text-gray-500 dark:text-amber-muted max-w-md">
              Choose a peer above to visualize its network connections. Connections fan out on both sides with animated lines showing traffic direction.
            </p>
          </div>
        ) : layoutData ? (
          <>
            <TreeGraph
              layoutData={layoutData}
              isDark={isDark}
              onNodeClick={handleNodeClick}
              onEdgeClick={handleEdgeClick}
              onGroupClick={handleGroupClick}
              onBackgroundClick={handleBackgroundClick}
            />
                <DetailPanel
                  selection={detailSelection}
                  onClose={() => setDetailSelection(null)}
                  onExpand={handleExpand}
                  onCollapse={handleCollapse}
                />
          </>
        ) : (
          <div className="flex flex-col items-center justify-center h-full text-center p-8">
            <div className="text-gray-400 dark:text-gray-600 mb-4">
              <svg className="w-16 h-16 mx-auto" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <circle cx="12" cy="12" r="3" />
                <path d="M12 2v4M12 18v4M2 12h4M18 12h4" strokeDasharray="2 2" />
              </svg>
            </div>
            <h3 className="text-lg font-semibold text-gray-700 dark:text-light-neutral mb-2">No Connections Found</h3>
            <p className="text-sm text-gray-500 dark:text-amber-muted max-w-md">
              This peer has no enabled ACCEPT policies connecting it to other peers or groups.
            </p>
          </div>
        )}
      </div>

      <style>{`
        @keyframes slide-in {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        .animate-slide-in { animation: slide-in 0.25s ease-out; }
      `}</style>
    </div>
  )
}
