'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { ArrowLeft, Shield, AlertTriangle, Zap, RefreshCw, TrendingUp } from 'lucide-react';

interface AlgorithmInfo {
    algorithm: string;
    instance_count: number;
    sample_locations: string[];
    is_pqc_vulnerable: boolean;
    is_quantum_safe: boolean;
    migration_priority: 'critical' | 'high' | 'medium' | 'low';
}

interface AgilityData {
    algorithms: AlgorithmInfo[];
    total_unique: number;
    vulnerable_count: number;
    quantum_safe_count: number;
}

export default function AgilityPage() {
    const [data, setData] = useState<AgilityData | null>(null);
    const [loading, setLoading] = useState(true);
    const [selectedAlgo, setSelectedAlgo] = useState<AlgorithmInfo | null>(null);
    const [filter, setFilter] = useState<'all' | 'vulnerable' | 'safe'>('all');

    useEffect(() => {
        async function fetchData() {
            try {
                const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/agility`);
                if (res.ok) {
                    const result = await res.json();
                    setData(result);
                }
            } catch (err) {
                console.error('Failed to load agility data:', err);
            } finally {
                setLoading(false);
            }
        }
        fetchData();
    }, []);

    const filteredAlgorithms = data?.algorithms.filter(a => {
        if (filter === 'vulnerable') return a.is_pqc_vulnerable;
        if (filter === 'safe') return a.is_quantum_safe;
        return true;
    }) || [];

    const priorityColors = {
        critical: 'bg-red-500/20 text-red-400 border-red-500/30',
        high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
        medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
        low: 'bg-green-500/20 text-green-400 border-green-500/30'
    };

    if (loading) {
        return (
            <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 flex items-center justify-center">
                <div className="animate-pulse text-white text-xl">Loading algorithm registry...</div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
            {/* Header */}
            <header className="border-b border-white/10 backdrop-blur-xl bg-black/20">
                <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
                    <div className="flex items-center gap-4">
                        <Link href="/" className="p-2 rounded-lg bg-white/5 hover:bg-white/10 transition">
                            <ArrowLeft className="w-5 h-5 text-white" />
                        </Link>
                        <div>
                            <h1 className="text-xl font-bold text-white flex items-center gap-2">
                                <RefreshCw className="w-5 h-5 text-cyan-400" />
                                Cryptographic Agility Dashboard
                            </h1>
                            <p className="text-sm text-gray-400">Track algorithm usage for rapid migration</p>
                        </div>
                    </div>

                    {data && (
                        <div className="flex items-center gap-6">
                            <div className="text-center">
                                <div className="text-2xl font-bold text-white">{data.total_unique}</div>
                                <div className="text-xs text-gray-400">Unique Algorithms</div>
                            </div>
                            <div className="text-center">
                                <div className="text-2xl font-bold text-red-400">{data.vulnerable_count}</div>
                                <div className="text-xs text-gray-400">PQC Vulnerable</div>
                            </div>
                            <div className="text-center">
                                <div className="text-2xl font-bold text-green-400">{data.quantum_safe_count}</div>
                                <div className="text-xs text-gray-400">Quantum Safe</div>
                            </div>
                        </div>
                    )}
                </div>
            </header>

            {/* Main Content */}
            <main className="max-w-7xl mx-auto px-6 py-8">
                {/* Filters */}
                <div className="flex gap-2 mb-6">
                    {[
                        { key: 'all', label: 'All Algorithms' },
                        { key: 'vulnerable', label: 'PQC Vulnerable' },
                        { key: 'safe', label: 'Quantum Safe' }
                    ].map(f => (
                        <button
                            key={f.key}
                            onClick={() => setFilter(f.key as any)}
                            className={`px-4 py-2 rounded-lg text-sm font-medium transition ${filter === f.key
                                    ? 'bg-purple-500 text-white'
                                    : 'bg-white/5 text-gray-300 hover:bg-white/10'
                                }`}
                        >
                            {f.label}
                        </button>
                    ))}
                </div>

                {/* Info Banner */}
                <div className="mb-6 p-4 rounded-xl bg-gradient-to-r from-cyan-500/10 to-purple-500/10 border border-cyan-500/20">
                    <div className="flex items-start gap-3">
                        <TrendingUp className="w-5 h-5 text-cyan-400 mt-0.5" />
                        <div>
                            <h3 className="font-medium text-white">Cryptographic Agility</h3>
                            <p className="text-sm text-gray-400 mt-1">
                                This registry tracks every cryptographic algorithm used across all scans.
                                If a PQC algorithm is found weak, you can instantly identify all affected locations.
                            </p>
                        </div>
                    </div>
                </div>

                {/* Algorithm Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {filteredAlgorithms.map(algo => (
                        <div
                            key={algo.algorithm}
                            onClick={() => setSelectedAlgo(algo)}
                            className={`p-4 rounded-xl border cursor-pointer transition transform hover:scale-[1.02] ${algo.is_quantum_safe
                                    ? 'bg-green-500/5 border-green-500/20 hover:border-green-500/40'
                                    : algo.is_pqc_vulnerable
                                        ? 'bg-red-500/5 border-red-500/20 hover:border-red-500/40'
                                        : 'bg-white/5 border-white/10 hover:border-white/20'
                                }`}
                        >
                            <div className="flex items-start justify-between">
                                <div>
                                    <div className="font-mono font-medium text-white">{algo.algorithm}</div>
                                    <div className="text-sm text-gray-400 mt-1">
                                        {algo.instance_count} instance{algo.instance_count !== 1 ? 's' : ''}
                                    </div>
                                </div>
                                <div className="flex items-center gap-2">
                                    {algo.is_quantum_safe && (
                                        <Shield className="w-5 h-5 text-green-400" />
                                    )}
                                    {algo.is_pqc_vulnerable && (
                                        <AlertTriangle className="w-5 h-5 text-red-400" />
                                    )}
                                </div>
                            </div>

                            <div className="mt-3 flex items-center gap-2">
                                <span className={`px-2 py-0.5 rounded-full text-xs font-medium border ${priorityColors[algo.migration_priority]}`}>
                                    {algo.migration_priority} priority
                                </span>
                            </div>

                            {algo.sample_locations.length > 0 && (
                                <div className="mt-3 text-xs text-gray-500 truncate">
                                    {algo.sample_locations[0].split('/').pop()}
                                </div>
                            )}
                        </div>
                    ))}
                </div>

                {filteredAlgorithms.length === 0 && (
                    <div className="text-center py-12">
                        <p className="text-gray-400">No algorithms found matching the filter.</p>
                    </div>
                )}
            </main>

            {/* Detail Modal */}
            {selectedAlgo && (
                <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50" onClick={() => setSelectedAlgo(null)}>
                    <div className="bg-slate-900 rounded-2xl border border-white/10 max-w-lg w-full mx-4 p-6" onClick={e => e.stopPropagation()}>
                        <div className="flex items-start justify-between mb-4">
                            <div>
                                <h2 className="text-xl font-bold text-white font-mono">{selectedAlgo.algorithm}</h2>
                                <p className="text-sm text-gray-400 mt-1">
                                    {selectedAlgo.instance_count} instance{selectedAlgo.instance_count !== 1 ? 's' : ''} across codebase
                                </p>
                            </div>
                            <div className="flex gap-2">
                                {selectedAlgo.is_quantum_safe && (
                                    <span className="px-2 py-1 rounded-full text-xs bg-green-500/20 text-green-400 border border-green-500/30">
                                        Quantum Safe
                                    </span>
                                )}
                                {selectedAlgo.is_pqc_vulnerable && (
                                    <span className="px-2 py-1 rounded-full text-xs bg-red-500/20 text-red-400 border border-red-500/30">
                                        PQC Vulnerable
                                    </span>
                                )}
                            </div>
                        </div>

                        <div className="mb-4">
                            <div className="text-xs text-gray-500 uppercase tracking-wide mb-2">Migration Priority</div>
                            <span className={`px-3 py-1 rounded-full text-sm font-medium border ${priorityColors[selectedAlgo.migration_priority]}`}>
                                {selectedAlgo.migration_priority.toUpperCase()}
                            </span>
                        </div>

                        <div className="mb-4">
                            <div className="text-xs text-gray-500 uppercase tracking-wide mb-2">Sample Locations</div>
                            <div className="space-y-1 max-h-32 overflow-y-auto">
                                {selectedAlgo.sample_locations.map((loc, i) => (
                                    <div key={i} className="text-sm text-gray-300 font-mono truncate bg-black/20 px-2 py-1 rounded">
                                        {loc}
                                    </div>
                                ))}
                                {selectedAlgo.sample_locations.length === 0 && (
                                    <p className="text-sm text-gray-500">No locations available</p>
                                )}
                            </div>
                        </div>

                        {selectedAlgo.is_pqc_vulnerable && (
                            <div className="p-3 rounded-lg bg-orange-500/10 border border-orange-500/20 mb-4">
                                <div className="flex items-start gap-2">
                                    <Zap className="w-4 h-4 text-orange-400 mt-0.5" />
                                    <div>
                                        <div className="text-sm font-medium text-orange-400">Migration Recommended</div>
                                        <p className="text-xs text-gray-400 mt-1">
                                            Replace with NIST PQC standard: ML-KEM (for encryption) or ML-DSA (for signatures)
                                        </p>
                                    </div>
                                </div>
                            </div>
                        )}

                        <button
                            onClick={() => setSelectedAlgo(null)}
                            className="w-full py-2 px-4 rounded-lg bg-white/5 hover:bg-white/10 text-white text-sm transition"
                        >
                            Close
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
}
