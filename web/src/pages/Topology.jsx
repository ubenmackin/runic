import { useState, useRef, useEffect, useCallback, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, QUERY_KEYS } from '../api/client'
import SearchableSelect from '../components/SearchableSelect'
import { RotateCcw, X, Maximize2, ChevronRight, Minus, Plus } from 'lucide-react'
import * as d3 from 'd3'

// ──────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────

const COLORS = {
  forward:    '#22c55e',   // green-500
  backward:   '#3b82f6',   // blue-500
  forwardDim: '#16a34a99', // green with alpha
  backwardDim:'#2563eb99', // blue with alpha
  peerOnline: '#a855f7',   // purple-500 (matches runic accent)
  peerOffline:'#6b7280',   // gray-500
  group:      '#f59e0b',   // amber-500
  startPeer:  '#a855f7',   // purple-500
  highlight:  '#f59e0b',   // amber
}

const DARK_COLORS = {
  bg:         '#1a1a2e',
  nodeFill:   '#2d2d4e',
  nodeStroke: '#4a4a6e',
  text:       '#e2e8f0',
  textMuted:  '#94a3b8',
  panelBg:    '#1e1e3a',
  panelBorder:'#3a3a5c',
}

const LIGHT_COLORS = {
  bg:         '#f8fafc',
  nodeFill:   '#ffffff',
  nodeStroke: '#d1d5db',
  text:       '#1f2937',
  textMuted:  '#6b7280',
  panelBg:    '#ffffff',
  panelBorder:'#e5e7eb',
}

// ──────────────────────────────────────────────────────
// Hook: resolve group members for all relevant groups
// ──────────────────────────────────────────────────────

function useGroupMembers(groupIds) {
  // Fetch members for each group in parallel using individual queries
  const queries = useQuery({
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
  return queries
}

// ──────────────────────────────────────────────────────
// Build topology graph data from APIs
// ──────────────────────────────────────────────────────

function buildGraph(startPeerId, peers, groups, policies, services, groupMembersMap) {
  if (!startPeerId || !peers?.length || !policies?.length) return { nodes: [], edges: [] }

  // Only enabled ACCEPT policies
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
    // Direct peer match
    if (p.source_type === 'peer' && p.source_id === startPeerId) return true
    if (p.target_type === 'peer' && p.target_id === startPeerId) return true
    // Group match
    if (p.source_type === 'group' && myGroupIds.has(p.source_id)) return true
    if (p.target_type === 'group' && myGroupIds.has(p.target_id)) return true
    return false
  })

  // Build nodes
  const nodesMap = new Map()

  // Always add starting peer
  const startPeer = peers.find(p => p.id === startPeerId)
  if (!startPeer) return { nodes: [], edges: [] }
  nodesMap.set(`peer-${startPeerId}`, {
    id: `peer-${startPeerId}`,
    type: 'peer',
    entityId: startPeerId,
    label: startPeer.hostname || startPeer.ip_address,
    data: startPeer,
    isStart: true,
  })

  // Add connected entities
  for (const pol of relevantPolicies) {
    // Add source
    const srcKey = `${pol.source_type}-${pol.source_id}`
    if (!nodesMap.has(srcKey)) {
      if (pol.source_type === 'peer') {
        const peer = peers.find(p => p.id === pol.source_id)
        if (peer) {
          nodesMap.set(srcKey, {
            id: srcKey, type: 'peer', entityId: pol.source_id,
            label: peer.hostname || peer.ip_address, data: peer, isStart: false,
          })
        }
      } else if (pol.source_type === 'group') {
        const group = groups.find(g => g.id === pol.source_id)
        if (group) {
          nodesMap.set(srcKey, {
            id: srcKey, type: 'group', entityId: pol.source_id,
            label: group.name, data: group, isStart: false,
            peerCount: group.peer_count || 0,
          })
        }
      }
    }

    // Add target
    const tgtKey = `${pol.target_type}-${pol.target_id}`
    if (!nodesMap.has(tgtKey)) {
      if (pol.target_type === 'peer') {
        const peer = peers.find(p => p.id === pol.target_id)
        if (peer) {
          nodesMap.set(tgtKey, {
            id: tgtKey, type: 'peer', entityId: pol.target_id,
            label: peer.hostname || peer.ip_address, data: peer, isStart: false,
          })
        }
      } else if (pol.target_type === 'group') {
        const group = groups.find(g => g.id === pol.target_id)
        if (group) {
          nodesMap.set(tgtKey, {
            id: tgtKey, type: 'group', entityId: pol.target_id,
            label: group.name, data: group, isStart: false,
            peerCount: group.peer_count || 0,
          })
        }
      } else if (pol.target_type === 'special') {
        // Skip specials for now - not useful in topology
      }
    }
  }

  // Build edges for each policy
  const edges = []
  for (const pol of relevantPolicies) {
    const srcKey = `${pol.source_type}-${pol.source_id}`
    const tgtKey = `${pol.target_type}-${pol.target_id}`

    // Skip edges where both nodes aren't in our graph
    if (!nodesMap.has(srcKey) || !nodesMap.has(tgtKey)) continue

    const serviceName = services?.find(s => s.id === pol.service_id)?.name || 'Unknown'
    const servicePorts = services?.find(s => s.id === pol.service_id)?.ports || ''

    if (pol.direction === 'both' || pol.direction === 'forward') {
      edges.push({
        id: `${pol.id}-fwd`,
        source: srcKey,
        target: tgtKey,
        direction: 'forward',
        policyId: pol.id,
        policyName: pol.name,
        serviceName,
        servicePorts,
        serviceId: pol.service_id,
      })
    }
    if (pol.direction === 'both' || pol.direction === 'backward') {
      edges.push({
        id: `${pol.id}-bwd`,
        source: tgtKey,
        target: srcKey,
        direction: 'backward',
        policyId: pol.id,
        policyName: pol.name,
        serviceName,
        servicePorts,
        serviceId: pol.service_id,
      })
    }
  }

  return {
    nodes: Array.from(nodesMap.values()),
    edges,
  }
}

// ──────────────────────────────────────────────────────
// Group explosion: replace a group node with its peers
// ──────────────────────────────────────────────────────

function explodeGroup(graph, groupNodeId, groupMembers, peers, expandedGroups) {
  const groupNode = graph.nodes.find(n => n.id === groupNodeId)
  if (!groupNode || groupNode.type !== 'group') return graph

  const newNodes = graph.nodes.filter(n => n.id !== groupNodeId)
  const memberPeerIds = (groupMembers || []).map(m => m.id)

  // Add member peers as nodes (if not already present)
  for (const memberId of memberPeerIds) {
    const memberKey = `peer-${memberId}`
    if (!newNodes.find(n => n.id === memberKey)) {
      const peer = peers.find(p => p.id === memberId)
      if (peer) {
        newNodes.push({
          id: memberKey,
          type: 'peer',
          entityId: memberId,
          label: peer.hostname || peer.ip_address,
          data: peer,
          isStart: false,
          fromGroup: groupNode.entityId,
          // Position near where the group was
          x: (groupNode.x || 0) + (Math.random() - 0.5) * 80,
          y: (groupNode.y || 0) + (Math.random() - 0.5) * 80,
        })
      }
    }
  }

  // Re-route edges: any edge pointing to/from the group now points to each member peer
  const newEdges = []
  for (const edge of graph.edges) {
    if (edge.source === groupNodeId || (edge.source && edge.source.id === groupNodeId)) {
      // Group was source → each member peer becomes source
      for (const memberId of memberPeerIds) {
        const memberKey = `peer-${memberId}`
        if (newNodes.find(n => n.id === memberKey)) {
          newEdges.push({ ...edge, id: `${edge.id}-exp-${memberId}`, source: memberKey })
        }
      }
    } else if (edge.target === groupNodeId || (edge.target && edge.target.id === groupNodeId)) {
      // Group was target → each member peer becomes target
      for (const memberId of memberPeerIds) {
        const memberKey = `peer-${memberId}`
        if (newNodes.find(n => n.id === memberKey)) {
          newEdges.push({ ...edge, id: `${edge.id}-exp-${memberId}`, target: memberKey })
        }
      }
    } else {
      newEdges.push(edge)
    }
  }

  return { nodes: newNodes, edges: newEdges }
}

// ──────────────────────────────────────────────────────
// D3 Force Graph Renderer
// ──────────────────────────────────────────────────────

function ForceGraph({ graph, isDark, onNodeClick, onEdgeClick, onGroupExpand }) {
  const svgRef = useRef(null)
  const containerRef = useRef(null)
  const simulationRef = useRef(null)
  const zoomRef = useRef(null)
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 })

  const colors = isDark ? DARK_COLORS : LIGHT_COLORS

  // Observe container size
  useEffect(() => {
    const container = containerRef.current
    if (!container) return
    const ro = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect
      if (width > 0 && height > 0) {
        setDimensions({ width, height })
      }
    })
    ro.observe(container)
    return () => ro.disconnect()
  }, [])

  // D3 force simulation
  useEffect(() => {
    if (!svgRef.current || !graph.nodes.length) return

    const svg = d3.select(svgRef.current)
    const { width, height } = dimensions

    // Clear previous
    svg.selectAll('*').remove()

    // Defs for arrow markers and animations
    const defs = svg.append('defs')

    // Glow filter for start node
    const glow = defs.append('filter').attr('id', 'glow')
    glow.append('feGaussianBlur').attr('stdDeviation', '4').attr('result', 'blur')
    glow.append('feMerge').selectAll('feMergeNode')
      .data(['blur', 'SourceGraphic'])
      .join('feMergeNode')
      .attr('in', d => d)

    // Container group for zoom/pan
    const g = svg.append('g').attr('class', 'graph-container')

    // Zoom behavior
    const zoom = d3.zoom()
      .scaleExtent([0.2, 4])
      .on('zoom', (event) => {
        g.attr('transform', event.transform)
      })
    svg.call(zoom)
    zoomRef.current = zoom

    // Prepare D3 node/link data (clone to avoid mutation)
    const nodes = graph.nodes.map(n => ({ ...n }))
    const links = graph.edges.map(e => ({
      ...e,
      source: typeof e.source === 'object' ? e.source.id : e.source,
      target: typeof e.target === 'object' ? e.target.id : e.target,
    }))

    // Group parallel edges by same source-target pair for offset
    const edgePairCount = {}
    const edgePairIndex = {}
    for (const link of links) {
      const pairKey = [link.source, link.target].sort().join('|')
      edgePairCount[pairKey] = (edgePairCount[pairKey] || 0) + 1
    }
    for (const link of links) {
      const pairKey = [link.source, link.target].sort().join('|')
      if (!edgePairIndex[pairKey]) edgePairIndex[pairKey] = 0
      link._pairIndex = edgePairIndex[pairKey]++
      link._pairTotal = edgePairCount[pairKey]
    }

    // Force simulation
    const simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(200))
      .force('charge', d3.forceManyBody().strength(-800))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(60))

    simulationRef.current = simulation

    // Edge elements (drawn first so they're behind nodes)
    const linkGroup = g.append('g').attr('class', 'links')

    const linkElements = linkGroup.selectAll('g.link-group')
      .data(links)
      .join('g')
      .attr('class', 'link-group')
      .style('cursor', 'pointer')
      .on('click', (event, d) => {
        event.stopPropagation()
        onEdgeClick?.(d)
      })

    // The actual animated path for each link
    const linkPaths = linkElements.append('path')
      .attr('fill', 'none')
      .attr('stroke', d => d.direction === 'forward' ? COLORS.forward : COLORS.backward)
      .attr('stroke-width', 2.5)
      .attr('stroke-dasharray', '8 4')
      .attr('opacity', 0.8)

    // Invisible wider hitbox for easier clicking
    const linkHitboxes = linkElements.append('path')
      .attr('fill', 'none')
      .attr('stroke', 'transparent')
      .attr('stroke-width', 20)

    // Service pills on links
    const pillGroups = linkElements.append('g').attr('class', 'pill')

    const pillRects = pillGroups.append('rect')
      .attr('rx', 10)
      .attr('ry', 10)
      .attr('fill', isDark ? '#2d2d4e' : '#ffffff')
      .attr('stroke', d => d.direction === 'forward' ? COLORS.forward : COLORS.backward)
      .attr('stroke-width', 1.5)
      .attr('opacity', 0.95)

    const pillTexts = pillGroups.append('text')
      .text(d => d.serviceName)
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'central')
      .attr('fill', d => d.direction === 'forward' ? COLORS.forward : COLORS.backward)
      .attr('font-size', '10px')
      .attr('font-weight', '600')
      .attr('font-family', 'Inter, system-ui, sans-serif')

    // Measure text widths and set rect widths
    pillTexts.each(function(d) {
      const bbox = this.getBBox()
      d._pillWidth = bbox.width + 16
      d._pillHeight = 20
    })
    pillRects
      .attr('width', d => d._pillWidth || 50)
      .attr('height', d => d._pillHeight || 20)

    // Arrow indicators on paths
    const arrowGroups = linkElements.append('g').attr('class', 'arrow')

    arrowGroups.append('polygon')
      .attr('points', '0,-5 10,0 0,5')
      .attr('fill', d => d.direction === 'forward' ? COLORS.forward : COLORS.backward)
      .attr('opacity', 0.9)

    // Node elements
    const nodeGroup = g.append('g').attr('class', 'nodes')

    const nodeElements = nodeGroup.selectAll('g.node')
      .data(nodes)
      .join('g')
      .attr('class', 'node')
      .style('cursor', 'pointer')
      .on('click', (event, d) => {
        event.stopPropagation()
        if (d.type === 'group') {
          onGroupExpand?.(d)
        } else {
          onNodeClick?.(d)
        }
      })

    // Drag behavior
    const drag = d3.drag()
      .on('start', (event, d) => {
        if (!event.active) simulation.alphaTarget(0.3).restart()
        d.fx = d.x
        d.fy = d.y
      })
      .on('drag', (event, d) => {
        d.fx = event.x
        d.fy = event.y
      })
      .on('end', (event, d) => {
        if (!event.active) simulation.alphaTarget(0)
        d.fx = null
        d.fy = null
      })

    nodeElements.call(drag)

    // Draw node shapes
    nodeElements.each(function(d) {
      const el = d3.select(this)

      if (d.isStart) {
        // Starting peer: larger circle with glow
        el.append('circle')
          .attr('r', 38)
          .attr('fill', COLORS.startPeer + '20')
          .attr('stroke', COLORS.startPeer)
          .attr('stroke-width', 3)
          .attr('filter', 'url(#glow)')

        el.append('circle')
          .attr('r', 32)
          .attr('fill', isDark ? DARK_COLORS.nodeFill : LIGHT_COLORS.nodeFill)
          .attr('stroke', COLORS.startPeer)
          .attr('stroke-width', 2)

      } else if (d.type === 'group') {
        // Group: hexagon shape
        const size = 35
        const hexPoints = Array.from({ length: 6 }, (_, i) => {
          const angle = (Math.PI / 3) * i - Math.PI / 6
          return `${Math.cos(angle) * size},${Math.sin(angle) * size}`
        }).join(' ')

        el.append('polygon')
          .attr('points', hexPoints)
          .attr('fill', isDark ? DARK_COLORS.nodeFill : LIGHT_COLORS.nodeFill)
          .attr('stroke', COLORS.group)
          .attr('stroke-width', 2.5)

        // Peer count badge
        const badgeGroup = el.append('g').attr('transform', `translate(20, -25)`)
        badgeGroup.append('circle')
          .attr('r', 10)
          .attr('fill', COLORS.group)
        badgeGroup.append('text')
          .text(d.peerCount || 0)
          .attr('text-anchor', 'middle')
          .attr('dominant-baseline', 'central')
          .attr('fill', '#fff')
          .attr('font-size', '9px')
          .attr('font-weight', 'bold')
          .attr('font-family', 'Inter, system-ui, sans-serif')

      } else {
        // Regular peer: circle
        const isOnline = d.data?.status === 'online'
        el.append('circle')
          .attr('r', 26)
          .attr('fill', isDark ? DARK_COLORS.nodeFill : LIGHT_COLORS.nodeFill)
          .attr('stroke', isOnline ? COLORS.peerOnline : COLORS.peerOffline)
          .attr('stroke-width', 2)

        // Status dot
        el.append('circle')
          .attr('cx', 18)
          .attr('cy', -18)
          .attr('r', 5)
          .attr('fill', isOnline ? '#22c55e' : '#ef4444')
          .attr('stroke', isDark ? DARK_COLORS.nodeFill : LIGHT_COLORS.nodeFill)
          .attr('stroke-width', 1.5)
      }

      // Label
      const labelY = d.type === 'group' ? 48 : (d.isStart ? 50 : 40)
      el.append('text')
        .text(d.label.length > 16 ? d.label.slice(0, 14) + '…' : d.label)
        .attr('text-anchor', 'middle')
        .attr('y', labelY)
        .attr('fill', colors.text)
        .attr('font-size', d.isStart ? '13px' : '11px')
        .attr('font-weight', d.isStart ? '700' : '500')
        .attr('font-family', 'Inter, system-ui, sans-serif')

      // Type badge below label
      if (d.type === 'group') {
        el.append('text')
          .text('GROUP')
          .attr('text-anchor', 'middle')
          .attr('y', labelY + 15)
          .attr('fill', COLORS.group)
          .attr('font-size', '8px')
          .attr('font-weight', '700')
          .attr('letter-spacing', '0.5px')
          .attr('font-family', 'Inter, system-ui, sans-serif')
      }
    })

    // Animation: flowing dashes
    let animFrame
    let animTime = 0
    function animateLinks() {
      animTime += 0.5
      linkPaths.attr('stroke-dashoffset', d => {
        return d.direction === 'forward' ? -animTime : animTime
      })
      animFrame = requestAnimationFrame(animateLinks)
    }
    animateLinks()

    // Tick function for simulation
    simulation.on('tick', () => {
      // Update link paths (curved for parallel edges)
      linkPaths.attr('d', d => {
        const sx = d.source.x, sy = d.source.y
        const tx = d.target.x, ty = d.target.y

        if (d._pairTotal > 1) {
          // Offset parallel lines with quadratic curves
          const dx = tx - sx, dy = ty - sy
          const len = Math.sqrt(dx * dx + dy * dy) || 1
          const offset = (d._pairIndex - (d._pairTotal - 1) / 2) * 30
          const mx = (sx + tx) / 2 + (-dy / len) * offset
          const my = (sy + ty) / 2 + (dx / len) * offset
          return `M${sx},${sy} Q${mx},${my} ${tx},${ty}`
        }
        return `M${sx},${sy} L${tx},${ty}`
      })

      linkHitboxes.attr('d', d => {
        const sx = d.source.x, sy = d.source.y
        const tx = d.target.x, ty = d.target.y
        if (d._pairTotal > 1) {
          const dx = tx - sx, dy = ty - sy
          const len = Math.sqrt(dx * dx + dy * dy) || 1
          const offset = (d._pairIndex - (d._pairTotal - 1) / 2) * 30
          const mx = (sx + tx) / 2 + (-dy / len) * offset
          const my = (sy + ty) / 2 + (dx / len) * offset
          return `M${sx},${sy} Q${mx},${my} ${tx},${ty}`
        }
        return `M${sx},${sy} L${tx},${ty}`
      })

      // Position pills at midpoint of each link
      pillGroups.attr('transform', d => {
        const sx = d.source.x, sy = d.source.y
        const tx = d.target.x, ty = d.target.y
        let mx, my
        if (d._pairTotal > 1) {
          const dx = tx - sx, dy = ty - sy
          const len = Math.sqrt(dx * dx + dy * dy) || 1
          const offset = (d._pairIndex - (d._pairTotal - 1) / 2) * 30
          // Midpoint of quadratic bezier: avg of start, control, end
          const cx = (sx + tx) / 2 + (-dy / len) * offset
          const cy = (sy + ty) / 2 + (dx / len) * offset
          mx = (sx + 2 * cx + tx) / 4
          my = (sy + 2 * cy + ty) / 4
        } else {
          mx = (sx + tx) / 2
          my = (sy + ty) / 2
        }
        return `translate(${mx - (d._pillWidth || 50) / 2}, ${my - (d._pillHeight || 20) / 2})`
      })

      pillTexts.attr('x', d => (d._pillWidth || 50) / 2)
               .attr('y', d => (d._pillHeight || 20) / 2)

      // Position arrow at ~75% along the path
      arrowGroups.attr('transform', d => {
        const sx = d.source.x, sy = d.source.y
        const tx = d.target.x, ty = d.target.y
        let px, py, angle
        if (d._pairTotal > 1) {
          const dx = tx - sx, dy = ty - sy
          const len = Math.sqrt(dx * dx + dy * dy) || 1
          const offset = (d._pairIndex - (d._pairTotal - 1) / 2) * 30
          const cx = (sx + tx) / 2 + (-dy / len) * offset
          const cy = (sy + ty) / 2 + (dx / len) * offset
          const t = 0.7
          px = (1 - t) * (1 - t) * sx + 2 * (1 - t) * t * cx + t * t * tx
          py = (1 - t) * (1 - t) * sy + 2 * (1 - t) * t * cy + t * t * ty
          // Tangent at t
          const tdx = 2 * (1 - t) * (cx - sx) + 2 * t * (tx - cx)
          const tdy = 2 * (1 - t) * (cy - sy) + 2 * t * (ty - cy)
          angle = Math.atan2(tdy, tdx) * 180 / Math.PI
        } else {
          px = sx + (tx - sx) * 0.7
          py = sy + (ty - sy) * 0.7
          angle = Math.atan2(ty - sy, tx - sx) * 180 / Math.PI
        }
        return `translate(${px},${py}) rotate(${angle})`
      })

      // Update node positions
      nodeElements.attr('transform', d => `translate(${d.x},${d.y})`)
    })

    // Initial zoom to fit
    setTimeout(() => {
      const bounds = g.node().getBBox()
      if (bounds.width > 0 && bounds.height > 0) {
        const padding = 80
        const fullWidth = bounds.width + padding * 2
        const fullHeight = bounds.height + padding * 2
        const scale = Math.min(width / fullWidth, height / fullHeight, 1.5)
        const tx = width / 2 - (bounds.x + bounds.width / 2) * scale
        const ty = height / 2 - (bounds.y + bounds.height / 2) * scale
        svg.transition().duration(750)
          .call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale))
      }
    }, 1500)

    return () => {
      cancelAnimationFrame(animFrame)
      simulation.stop()
    }
  }, [graph, dimensions, isDark])

  // Zoom controls
  const handleZoomIn = useCallback(() => {
    const svg = d3.select(svgRef.current)
    svg.transition().duration(300).call(zoomRef.current.scaleBy, 1.3)
  }, [])

  const handleZoomOut = useCallback(() => {
    const svg = d3.select(svgRef.current)
    svg.transition().duration(300).call(zoomRef.current.scaleBy, 0.7)
  }, [])

  const handleRecenter = useCallback(() => {
    const svg = d3.select(svgRef.current)
    const g = svg.select('g.graph-container')
    const bounds = g.node()?.getBBox()
    if (!bounds || bounds.width === 0) return
    const { width, height } = dimensions
    const padding = 80
    const fullWidth = bounds.width + padding * 2
    const fullHeight = bounds.height + padding * 2
    const scale = Math.min(width / fullWidth, height / fullHeight, 1.5)
    const tx = width / 2 - (bounds.x + bounds.width / 2) * scale
    const ty = height / 2 - (bounds.y + bounds.height / 2) * scale
    svg.transition().duration(500)
      .call(zoomRef.current.transform, d3.zoomIdentity.translate(tx, ty).scale(scale))
  }, [dimensions])

  return (
    <div ref={containerRef} className="relative w-full h-full" style={{ minHeight: '500px' }}>
      <svg
        ref={svgRef}
        width={dimensions.width}
        height={dimensions.height}
        style={{ background: colors.bg }}
        className="rounded-lg"
      />
      {/* Zoom controls */}
      <div className="absolute bottom-4 right-4 flex flex-col gap-1">
        <button onClick={handleZoomIn} className="p-2 rounded-lg bg-white dark:bg-charcoal-dark shadow-md border border-gray-200 dark:border-gray-border hover:bg-gray-50 dark:hover:bg-charcoal-darkest transition-colors" title="Zoom in">
          <Plus className="w-4 h-4 text-gray-700 dark:text-light-neutral" />
        </button>
        <button onClick={handleZoomOut} className="p-2 rounded-lg bg-white dark:bg-charcoal-dark shadow-md border border-gray-200 dark:border-gray-border hover:bg-gray-50 dark:hover:bg-charcoal-darkest transition-colors" title="Zoom out">
          <Minus className="w-4 h-4 text-gray-700 dark:text-light-neutral" />
        </button>
        <button onClick={handleRecenter} className="p-2 rounded-lg bg-white dark:bg-charcoal-dark shadow-md border border-gray-200 dark:border-gray-border hover:bg-gray-50 dark:hover:bg-charcoal-darkest transition-colors" title="Fit to view">
          <Maximize2 className="w-4 h-4 text-gray-700 dark:text-light-neutral" />
        </button>
      </div>
      {/* Legend */}
      <div className="absolute top-4 left-4 bg-white/90 dark:bg-charcoal-dark/90 backdrop-blur-sm rounded-lg p-3 shadow-md border border-gray-200 dark:border-gray-border text-xs space-y-2">
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
          <svg width="16" height="16" viewBox="0 0 16 16"><circle cx="8" cy="8" r="6" fill="none" stroke={COLORS.peerOnline} strokeWidth="2" /></svg>
          <span className="text-gray-600 dark:text-gray-400">Peer</span>
        </div>
        <div className="flex items-center gap-2">
          <svg width="16" height="16" viewBox="0 0 16 16">
            <polygon points="8,1 14.5,5 14.5,11 8,15 1.5,11 1.5,5" fill="none" stroke={COLORS.group} strokeWidth="1.5" />
          </svg>
          <span className="text-gray-600 dark:text-gray-400">Group (click to expand)</span>
        </div>
      </div>
    </div>
  )
}

// ──────────────────────────────────────────────────────
// Detail Panel
// ──────────────────────────────────────────────────────

function DetailPanel({ selection, onClose, onExpand, isDark }) {
  if (!selection) return null

  const { type, data } = selection

  return (
    <div className="absolute top-0 right-0 h-full w-80 bg-white dark:bg-charcoal-dark border-l border-gray-200 dark:border-gray-border shadow-xl z-10 flex flex-col overflow-hidden animate-slide-in">
      {/* Header */}
      <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-border flex items-center justify-between shrink-0">
        <h3 className="font-semibold text-gray-900 dark:text-light-neutral text-sm">
          {type === 'peer' ? 'Peer Details' : type === 'group' ? 'Group Details' : 'Connection Details'}
        </h3>
        <button onClick={onClose} className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded">
          <X className="w-4 h-4 text-gray-400" />
        </button>
      </div>

      {/* Content */}
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
                <span className={`w-2 h-2 rounded-full ${data.data?.status === 'online' ? 'bg-green-500' : 'bg-red-500'}`} />
                <span className="text-sm text-gray-900 dark:text-light-neutral capitalize">{data.data?.status || 'unknown'}</span>
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
              <div className="mt-2 px-3 py-2 bg-purple-50 dark:bg-purple-active/10 rounded-lg border border-purple-200 dark:border-purple-active/30">
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
            <button
              onClick={() => onExpand?.(data)}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 hover:bg-amber-100 dark:hover:bg-amber-500/20 text-amber-700 dark:text-amber-400 text-sm font-medium rounded-lg transition-colors"
            >
              Expand Group
              <ChevronRight className="w-4 h-4" />
            </button>
          </>
        )}

        {type === 'edge' && (
          <>
            <div>
              <div className="text-xs text-gray-500 dark:text-amber-muted uppercase tracking-wide mb-1">Policy</div>
              <div className="text-sm font-medium text-gray-900 dark:text-light-neutral">{data.policyName}</div>
            </div>
            <div>
              <div className="text-xs text-gray-500 dark:text-amber-muted uppercase tracking-wide mb-1">Direction</div>
              <div className="flex items-center gap-2">
                <span className="w-3 h-0.5 block" style={{ background: data.direction === 'forward' ? COLORS.forward : COLORS.backward }} />
                <span className="text-sm text-gray-900 dark:text-light-neutral capitalize">{data.direction}</span>
              </div>
            </div>
            <div>
              <div className="text-xs text-gray-500 dark:text-amber-muted uppercase tracking-wide mb-1">Service</div>
              <div className="text-sm text-gray-900 dark:text-light-neutral">{data.serviceName}</div>
            </div>
            {data.servicePorts && (
              <div>
                <div className="text-xs text-gray-500 dark:text-amber-muted uppercase tracking-wide mb-1">Ports</div>
                <div className="flex flex-wrap gap-1.5">
                  {data.servicePorts.split(',').map((p, i) => (
                    <span key={i} className="px-2 py-0.5 text-xs font-mono rounded-full bg-gray-100 dark:bg-charcoal-darkest text-gray-700 dark:text-gray-300">{p.trim()}</span>
                  ))}
                </div>
              </div>
            )}
          </>
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

  // Detect dark mode
  const [isDark, setIsDark] = useState(() => document.documentElement.classList.contains('dark'))
  useEffect(() => {
    const observer = new MutationObserver(() => {
      setIsDark(document.documentElement.classList.contains('dark'))
    })
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
    return () => observer.disconnect()
  }, [])

  // Fetch data
  const { data: peers } = useQuery({
    queryKey: QUERY_KEYS.peers(),
    queryFn: () => api.get('/peers'),
  })

  const { data: groups } = useQuery({
    queryKey: QUERY_KEYS.groups(),
    queryFn: () => api.get('/groups'),
  })

  const { data: policies } = useQuery({
    queryKey: QUERY_KEYS.policies(),
    queryFn: () => api.get('/policies'),
  })

  const { data: services } = useQuery({
    queryKey: QUERY_KEYS.services(),
    queryFn: () => api.get('/services'),
  })

  // Determine which group IDs we need members for
  const relevantGroupIds = useMemo(() => {
    if (!policies || !groups) return []
    const groupIds = new Set()
    policies.forEach(p => {
      if (p.enabled && p.action === 'ACCEPT') {
        if (p.source_type === 'group') groupIds.add(p.source_id)
        if (p.target_type === 'group') groupIds.add(p.target_id)
      }
    })
    return Array.from(groupIds)
  }, [policies, groups])

  const { data: groupMembersMap } = useGroupMembers(relevantGroupIds)

  // Build graph
  const baseGraph = useMemo(() =>
    buildGraph(selectedPeerId, peers, groups, policies, services, groupMembersMap),
    [selectedPeerId, peers, groups, policies, services, groupMembersMap]
  )

  // Apply group expansions
  const graph = useMemo(() => {
    let g = baseGraph
    for (const groupId of expandedGroups) {
      const groupNodeId = `group-${groupId}`
      const members = groupMembersMap?.[groupId] || []
      g = explodeGroup(g, groupNodeId, members, peers || [], expandedGroups)
    }
    return g
  }, [baseGraph, expandedGroups, groupMembersMap, peers])

  // Peer options for selector
  const peerOptions = useMemo(() =>
    (peers || []).map(p => ({
      value: p.id,
      label: p.hostname || p.ip_address,
    })),
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

  const handleGroupExpand = useCallback((groupNode) => {
    // Show detail panel first
    setDetailSelection({ type: 'group', data: groupNode })
  }, [])

  const handleDoExpand = useCallback((groupNode) => {
    setExpandedGroups(prev => {
      const next = new Set(prev)
      next.add(groupNode.entityId)
      return next
    })
    setDetailSelection(null)
  }, [])

  const hasGraph = graph.nodes.length > 0

  return (
    <div className="space-y-4 h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between shrink-0">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-light-neutral">Topology</h1>
          <p className="text-gray-600 dark:text-amber-muted">Visualize network connections between peers and groups</p>
        </div>
        <div className="flex items-center gap-3">
          {selectedPeerId && (
            <button
              onClick={handleReset}
              className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-700 dark:text-amber-primary bg-white dark:bg-charcoal-dark border border-gray-300 dark:border-gray-border rounded-lg hover:bg-gray-50 dark:hover:bg-charcoal-darkest"
            >
              <RotateCcw className="w-4 h-4" />
              Reset
            </button>
          )}
        </div>
      </div>

      {/* Peer Selector */}
      <div className="shrink-0 bg-white dark:bg-charcoal-dark rounded-xl shadow-sm p-4 border border-gray-200 dark:border-gray-border">
        <div className="flex items-center gap-4">
          <label className="text-sm font-medium text-gray-700 dark:text-amber-primary whitespace-nowrap">Starting Peer</label>
          <div className="w-72">
            <SearchableSelect
              options={peerOptions}
              value={selectedPeerId || ''}
              onChange={handlePeerSelect}
              placeholder="Select a peer to explore…"
            />
          </div>
          {selectedPeerId && !hasGraph && (
            <span className="text-sm text-gray-500 dark:text-amber-muted italic">
              No enabled ACCEPT policies involve this peer.
            </span>
          )}
          {hasGraph && (
            <span className="text-sm text-gray-500 dark:text-amber-muted">
              {graph.nodes.length} nodes · {graph.edges.length} connections
            </span>
          )}
        </div>
      </div>

      {/* Graph Area */}
      <div className="flex-1 relative bg-white dark:bg-charcoal-dark rounded-xl shadow-sm border border-gray-200 dark:border-gray-border overflow-hidden" style={{ minHeight: '500px' }}>
        {!selectedPeerId ? (
          <div className="flex flex-col items-center justify-center h-full text-center p-8">
            <svg className="w-24 h-24 mb-6 text-gray-300 dark:text-gray-600" viewBox="0 0 100 100" fill="none">
              <circle cx="30" cy="30" r="10" stroke="currentColor" strokeWidth="2" />
              <circle cx="70" cy="30" r="10" stroke="currentColor" strokeWidth="2" />
              <circle cx="50" cy="70" r="10" stroke="currentColor" strokeWidth="2" />
              <line x1="38" y1="34" x2="42" y2="62" stroke="currentColor" strokeWidth="1.5" strokeDasharray="4 3" />
              <line x1="62" y1="34" x2="58" y2="62" stroke="currentColor" strokeWidth="1.5" strokeDasharray="4 3" />
              <line x1="40" y1="30" x2="60" y2="30" stroke="currentColor" strokeWidth="1.5" strokeDasharray="4 3" />
            </svg>
            <h3 className="text-lg font-semibold text-gray-700 dark:text-light-neutral mb-2">Select a Starting Peer</h3>
            <p className="text-sm text-gray-500 dark:text-amber-muted max-w-md">
              Choose a peer above to visualize its network connections. You'll see all peers and groups
              it connects to via enabled policies, with animated lines showing traffic direction.
            </p>
          </div>
        ) : hasGraph ? (
          <>
            <ForceGraph
              graph={graph}
              isDark={isDark}
              onNodeClick={handleNodeClick}
              onEdgeClick={handleEdgeClick}
              onGroupExpand={handleGroupExpand}
            />
            <DetailPanel
              selection={detailSelection}
              onClose={() => setDetailSelection(null)}
              onExpand={handleDoExpand}
              isDark={isDark}
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
              Create policies on the Policies page to see connections here.
            </p>
          </div>
        )}
      </div>

      {/* CSS for slide-in animation */}
      <style>{`
        @keyframes slide-in {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        .animate-slide-in {
          animation: slide-in 0.25s ease-out;
        }
      `}</style>
    </div>
  )
}
