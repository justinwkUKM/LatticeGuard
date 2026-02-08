'use client';

import { useEffect, useRef, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { ArrowLeft, AlertTriangle, Shield, Zap, Network } from 'lucide-react';

interface GraphNode {
    id: string;
    label: string;
    group: 'root' | 'algorithm' | 'finding';
    risk: 'critical' | 'high' | 'medium' | 'low' | 'info';
    color: string;
    size: number;
    algorithm?: string;
    path?: string;
    x?: number;
    y?: number;
    vx?: number;
    vy?: number;
}

interface GraphEdge {
    source: string | GraphNode;
    target: string | GraphNode;
    type: 'uses' | 'contains';
}

interface GraphData {
    nodes: GraphNode[];
    edges: GraphEdge[];
    summary: {
        total_assets: number;
        algorithm_families: number;
        critical_nodes: number;
        high_risk_nodes: number;
        blast_radius_score: number;
    };
}

export default function BlastRadiusPage() {
    const params = useParams();
    const canvasRef = useRef<HTMLCanvasElement>(null);
    const [graphData, setGraphData] = useState<GraphData | null>(null);
    const [loading, setLoading] = useState(true);
    const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
    const [hoveredNode, setHoveredNode] = useState<GraphNode | null>(null);

    useEffect(() => {
        async function fetchGraph() {
            try {
                const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/reports/${params.id}/graph`);
                if (res.ok) {
                    const data = await res.json();
                    setGraphData(data);
                }
            } catch (err) {
                console.error('Failed to load graph:', err);
            } finally {
                setLoading(false);
            }
        }
        fetchGraph();
    }, [params.id]);

    useEffect(() => {
        if (!graphData || !canvasRef.current) return;

        const canvas = canvasRef.current;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        // Set canvas size
        const rect = canvas.getBoundingClientRect();
        canvas.width = rect.width * window.devicePixelRatio;
        canvas.height = rect.height * window.devicePixelRatio;
        ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

        const width = rect.width;
        const height = rect.height;
        const centerX = width / 2;
        const centerY = height / 2;

        // Initialize node positions
        const nodes = graphData.nodes.map((n, i) => ({
            ...n,
            x: n.group === 'root' ? centerX : centerX + (Math.random() - 0.5) * 400,
            y: n.group === 'root' ? centerY : centerY + (Math.random() - 0.5) * 400,
            vx: 0,
            vy: 0
        }));

        // Create edges with node references
        const edges = graphData.edges.map(e => ({
            ...e,
            source: nodes.find(n => n.id === e.source) || nodes[0],
            target: nodes.find(n => n.id === e.target) || nodes[0]
        }));

        // Force simulation
        let animationId: number;
        const simulate = () => {
            // Apply forces
            for (const node of nodes) {
                if (node.group === 'root') continue;

                // Center gravity
                node.vx += (centerX - node.x) * 0.001;
                node.vy += (centerY - node.y) * 0.001;

                // Repulsion between nodes
                for (const other of nodes) {
                    if (node === other) continue;
                    const dx = node.x - other.x;
                    const dy = node.y - other.y;
                    const dist = Math.sqrt(dx * dx + dy * dy) || 1;
                    const force = 500 / (dist * dist);
                    node.vx += (dx / dist) * force;
                    node.vy += (dy / dist) * force;
                }
            }

            // Apply edge constraints
            for (const edge of edges) {
                const source = edge.source as GraphNode;
                const target = edge.target as GraphNode;
                const dx = target.x! - source.x!;
                const dy = target.y! - source.y!;
                const dist = Math.sqrt(dx * dx + dy * dy) || 1;
                const targetDist = 120;
                const force = (dist - targetDist) * 0.01;

                if (source.group !== 'root') {
                    source.vx! += (dx / dist) * force;
                    source.vy! += (dy / dist) * force;
                }
                if (target.group !== 'root') {
                    target.vx! -= (dx / dist) * force;
                    target.vy! -= (dy / dist) * force;
                }
            }

            // Update positions with damping
            for (const node of nodes) {
                node.vx! *= 0.9;
                node.vy! *= 0.9;
                node.x! += node.vx!;
                node.y! += node.vy!;

                // Keep in bounds
                node.x = Math.max(50, Math.min(width - 50, node.x!));
                node.y = Math.max(50, Math.min(height - 50, node.y!));
            }

            // Draw
            ctx.clearRect(0, 0, width, height);

            // Draw edges
            ctx.strokeStyle = 'rgba(100, 100, 100, 0.3)';
            ctx.lineWidth = 1;
            for (const edge of edges) {
                const source = edge.source as GraphNode;
                const target = edge.target as GraphNode;
                ctx.beginPath();
                ctx.moveTo(source.x!, source.y!);
                ctx.lineTo(target.x!, target.y!);
                ctx.stroke();
            }

            // Draw nodes
            for (const node of nodes) {
                // Glow effect for high-risk nodes
                if (node.risk === 'critical' || node.risk === 'high') {
                    ctx.beginPath();
                    ctx.arc(node.x!, node.y!, node.size + 8, 0, Math.PI * 2);
                    ctx.fillStyle = node.color + '40';
                    ctx.fill();
                }

                // Node circle
                ctx.beginPath();
                ctx.arc(node.x!, node.y!, node.size, 0, Math.PI * 2);
                ctx.fillStyle = node.color;
                ctx.fill();
                ctx.strokeStyle = '#fff';
                ctx.lineWidth = 2;
                ctx.stroke();

                // Label for algorithm nodes
                if (node.group === 'algorithm' || node.group === 'root') {
                    ctx.fillStyle = '#fff';
                    ctx.font = '11px Inter, system-ui, sans-serif';
                    ctx.textAlign = 'center';
                    ctx.fillText(node.label, node.x!, node.y! + node.size + 14);
                }
            }

            animationId = requestAnimationFrame(simulate);
        };

        simulate();

        // Mouse interaction
        const handleMouseMove = (e: MouseEvent) => {
            const rect = canvas.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;

            for (const node of nodes) {
                const dx = x - node.x!;
                const dy = y - node.y!;
                if (Math.sqrt(dx * dx + dy * dy) < node.size) {
                    setHoveredNode(node);
                    canvas.style.cursor = 'pointer';
                    return;
                }
            }
            setHoveredNode(null);
            canvas.style.cursor = 'default';
        };

        const handleClick = (e: MouseEvent) => {
            const rect = canvas.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;

            for (const node of nodes) {
                const dx = x - node.x!;
                const dy = y - node.y!;
                if (Math.sqrt(dx * dx + dy * dy) < node.size) {
                    setSelectedNode(node);
                    return;
                }
            }
            setSelectedNode(null);
        };

        canvas.addEventListener('mousemove', handleMouseMove);
        canvas.addEventListener('click', handleClick);

        return () => {
            cancelAnimationFrame(animationId);
            canvas.removeEventListener('mousemove', handleMouseMove);
            canvas.removeEventListener('click', handleClick);
        };
    }, [graphData]);

    if (loading) {
        return (
            <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 flex items-center justify-center">
                <div className="animate-pulse text-white text-xl">Loading graph...</div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
            {/* Header */}
            <header className="border-b border-white/10 backdrop-blur-xl bg-black/20">
                <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
                    <div className="flex items-center gap-4">
                        <Link href={`/history/${params.id}`} className="p-2 rounded-lg bg-white/5 hover:bg-white/10 transition">
                            <ArrowLeft className="w-5 h-5 text-white" />
                        </Link>
                        <div>
                            <h1 className="text-xl font-bold text-white flex items-center gap-2">
                                <Network className="w-5 h-5 text-purple-400" />
                                Blast Radius Visualization
                            </h1>
                            <p className="text-sm text-gray-400">{params.id}</p>
                        </div>
                    </div>

                    {graphData && (
                        <div className="flex items-center gap-6">
                            <div className="text-center">
                                <div className="text-2xl font-bold text-white">{graphData.summary.total_assets}</div>
                                <div className="text-xs text-gray-400">Assets</div>
                            </div>
                            <div className="text-center">
                                <div className="text-2xl font-bold text-orange-400">{graphData.summary.high_risk_nodes}</div>
                                <div className="text-xs text-gray-400">High Risk</div>
                            </div>
                            <div className="text-center">
                                <div className="text-2xl font-bold text-red-400">{graphData.summary.critical_nodes}</div>
                                <div className="text-xs text-gray-400">Critical</div>
                            </div>
                            <div className="px-4 py-2 rounded-lg bg-gradient-to-r from-purple-500/20 to-pink-500/20 border border-purple-500/30">
                                <div className="text-sm text-gray-400">Blast Radius Score</div>
                                <div className="text-2xl font-bold text-white">{graphData.summary.blast_radius_score.toFixed(1)}/10</div>
                            </div>
                        </div>
                    )}
                </div>
            </header>

            {/* Main Content */}
            <div className="flex h-[calc(100vh-80px)]">
                {/* Canvas */}
                <div className="flex-1 relative">
                    <canvas
                        ref={canvasRef}
                        className="w-full h-full"
                    />

                    {/* Legend */}
                    <div className="absolute bottom-6 left-6 p-4 rounded-xl bg-black/40 backdrop-blur-xl border border-white/10">
                        <div className="text-sm font-medium text-white mb-3">Risk Legend</div>
                        <div className="space-y-2">
                            {[
                                { color: '#ef4444', label: 'Critical' },
                                { color: '#f97316', label: 'High' },
                                { color: '#eab308', label: 'Medium' },
                                { color: '#22c55e', label: 'Low' },
                                { color: '#3b82f6', label: 'Root' }
                            ].map(item => (
                                <div key={item.label} className="flex items-center gap-2">
                                    <div className="w-3 h-3 rounded-full" style={{ backgroundColor: item.color }} />
                                    <span className="text-xs text-gray-300">{item.label}</span>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Hover tooltip */}
                    {hoveredNode && (
                        <div className="absolute top-6 left-6 p-4 rounded-xl bg-black/60 backdrop-blur-xl border border-white/10 max-w-sm">
                            <div className="font-medium text-white">{hoveredNode.label}</div>
                            {hoveredNode.algorithm && (
                                <div className="text-sm text-gray-400 mt-1">Algorithm: {hoveredNode.algorithm}</div>
                            )}
                            {hoveredNode.path && (
                                <div className="text-xs text-gray-500 mt-1 truncate">{hoveredNode.path}</div>
                            )}
                        </div>
                    )}
                </div>

                {/* Details Panel */}
                {selectedNode && (
                    <div className="w-80 border-l border-white/10 bg-black/20 backdrop-blur-xl p-6 overflow-y-auto">
                        <h3 className="text-lg font-bold text-white mb-4">Node Details</h3>

                        <div className="space-y-4">
                            <div>
                                <div className="text-xs text-gray-500 uppercase tracking-wide">Name</div>
                                <div className="text-white font-medium">{selectedNode.label}</div>
                            </div>

                            <div>
                                <div className="text-xs text-gray-500 uppercase tracking-wide">Type</div>
                                <div className="text-white capitalize">{selectedNode.group}</div>
                            </div>

                            <div>
                                <div className="text-xs text-gray-500 uppercase tracking-wide">Risk Level</div>
                                <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-sm font-medium ${selectedNode.risk === 'critical' ? 'bg-red-500/20 text-red-400' :
                                        selectedNode.risk === 'high' ? 'bg-orange-500/20 text-orange-400' :
                                            selectedNode.risk === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                                                'bg-green-500/20 text-green-400'
                                    }`}>
                                    {selectedNode.risk === 'critical' && <AlertTriangle className="w-4 h-4" />}
                                    {selectedNode.risk === 'high' && <Zap className="w-4 h-4" />}
                                    {selectedNode.risk === 'low' && <Shield className="w-4 h-4" />}
                                    {selectedNode.risk.toUpperCase()}
                                </div>
                            </div>

                            {selectedNode.algorithm && (
                                <div>
                                    <div className="text-xs text-gray-500 uppercase tracking-wide">Algorithm</div>
                                    <div className="text-white font-mono">{selectedNode.algorithm}</div>
                                </div>
                            )}

                            {selectedNode.path && (
                                <div>
                                    <div className="text-xs text-gray-500 uppercase tracking-wide">File Path</div>
                                    <div className="text-gray-300 text-sm break-all">{selectedNode.path}</div>
                                </div>
                            )}
                        </div>

                        <button
                            onClick={() => setSelectedNode(null)}
                            className="mt-6 w-full py-2 px-4 rounded-lg bg-white/5 hover:bg-white/10 text-white text-sm transition"
                        >
                            Close
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
}
