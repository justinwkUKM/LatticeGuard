'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
    Activity,
    Zap,
    Shield,
    TrendingUp,
    AlertCircle,
    PieChart as PieChartIcon,
    BarChart3
} from 'lucide-react';
import {
    AreaChart,
    Area,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
    BarChart,
    Bar,
    Cell,
    PieChart,
    Pie
} from 'recharts';
import { fetchMetricsTrends } from '@/lib/api';

const COLORS = ['#22d3ee', '#a855f7', '#f43f5e', '#fbbf24', '#10b981'];

export default function MetricsPage() {
    const [trends, setTrends] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        async function loadMetrics() {
            try {
                const data = await fetchMetricsTrends();
                setTrends(data);
            } catch (err) {
                console.error('Failed to load metrics:', err);
            } finally {
                setLoading(false);
            }
        }
        loadMetrics();
    }, []);

    const algoDist = [
        { name: 'RSA-2048', value: 45 },
        { name: 'ECDSA', value: 25 },
        { name: 'Diffie-Hellman', value: 20 },
        { name: 'Pure PQC', value: 10 },
    ];

    return (
        <div className="space-y-8 max-w-7xl mx-auto pb-20">
            <header>
                <h1 className="text-3xl font-extrabold text-white tracking-tight">Security Intelligence</h1>
                <p className="text-muted-foreground mt-1">Deep analytics and longitudinal risk trends across your infrastructure.</p>
            </header>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* Longitudinal Risk Trend */}
                <section className="lg:col-span-2 glass rounded-3xl p-8 border border-white/5">
                    <div className="flex items-center justify-between mb-8">
                        <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center text-primary">
                                <TrendingUp size={20} />
                            </div>
                            <h3 className="font-bold text-white text-lg">Risk Evolution</h3>
                        </div>
                        <div className="text-xs font-mono text-muted-foreground bg-white/5 px-2 py-1 rounded-md">
                            LAST_7_DAYS
                        </div>
                    </div>

                    <div className="h-[300px] w-full">
                        {loading ? (
                            <div className="w-full h-full bg-white/5 animate-pulse rounded-2xl" />
                        ) : (
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={trends}>
                                    <defs>
                                        <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.3} />
                                            <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
                                        </linearGradient>
                                        <linearGradient id="colorResolved" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                                            <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                                        </linearGradient>
                                    </defs>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#ffffff05" vertical={false} />
                                    <XAxis
                                        dataKey="name"
                                        stroke="#ffffff40"
                                        fontSize={12}
                                        tickLine={false}
                                        axisLine={false}
                                        className="font-mono"
                                    />
                                    <YAxis
                                        stroke="#ffffff40"
                                        fontSize={12}
                                        tickLine={false}
                                        axisLine={false}
                                        className="font-mono"
                                    />
                                    <Tooltip
                                        contentStyle={{
                                            backgroundColor: '#0f172a',
                                            borderColor: '#ffffff10',
                                            borderRadius: '12px',
                                            color: '#fff'
                                        }}
                                        itemStyle={{ color: '#22d3ee' }}
                                    />
                                    <Area
                                        type="monotone"
                                        dataKey="risks"
                                        name="Critical Risks"
                                        stroke="#22d3ee"
                                        strokeWidth={3}
                                        fillOpacity={1}
                                        fill="url(#colorRisk)"
                                    />
                                    <Area
                                        type="monotone"
                                        dataKey="resolved"
                                        name="Resolved"
                                        stroke="#10b981"
                                        strokeWidth={3}
                                        fillOpacity={1}
                                        fill="url(#colorResolved)"
                                    />
                                </AreaChart>
                            </ResponsiveContainer>
                        )}
                    </div>
                </section>

                {/* Algorithm Distribution */}
                <section className="glass rounded-3xl p-8 border border-white/5">
                    <div className="flex items-center gap-3 mb-8">
                        <div className="w-10 h-10 rounded-xl bg-purple-500/10 flex items-center justify-center text-purple-500">
                            <PieChartIcon size={20} />
                        </div>
                        <h3 className="font-bold text-white text-lg">Algo Landscape</h3>
                    </div>

                    <div className="h-[250px] w-full">
                        <ResponsiveContainer width="100%" height="100%">
                            <PieChart>
                                <Pie
                                    data={algoDist}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={60}
                                    outerRadius={80}
                                    paddingAngle={5}
                                    dataKey="value"
                                >
                                    {algoDist.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                    ))}
                                </Pie>
                                <Tooltip
                                    contentStyle={{
                                        backgroundColor: '#0f172a',
                                        borderColor: '#ffffff10',
                                        borderRadius: '12px',
                                        color: '#fff'
                                    }}
                                />
                            </PieChart>
                        </ResponsiveContainer>
                    </div>

                    <div className="mt-4 space-y-2">
                        {algoDist.map((item, index) => (
                            <div key={item.name} className="flex items-center justify-between text-xs">
                                <div className="flex items-center gap-2 text-muted-foreground">
                                    <div className="w-2 h-2 rounded-full" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                                    {item.name}
                                </div>
                                <div className="font-bold text-white">{item.value}%</div>
                            </div>
                        ))}
                    </div>
                </section>

                {/* Scan Frequency */}
                <section className="lg:col-span-3 glass rounded-3xl p-8 border border-white/5">
                    <div className="flex items-center gap-3 mb-8">
                        <div className="w-10 h-10 rounded-xl bg-emerald-500/10 flex items-center justify-center text-emerald-500">
                            <BarChart3 size={20} />
                        </div>
                        <h3 className="font-bold text-white text-lg">Activity Volume</h3>
                    </div>

                    <div className="h-[200px] w-full">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={trends}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff05" vertical={false} />
                                <XAxis
                                    dataKey="name"
                                    stroke="#ffffff40"
                                    fontSize={12}
                                    tickLine={false}
                                    axisLine={false}
                                    className="font-mono"
                                />
                                <Tooltip
                                    contentStyle={{
                                        backgroundColor: '#0f172a',
                                        borderColor: '#ffffff10',
                                        borderRadius: '12px',
                                        color: '#fff'
                                    }}
                                />
                                <Bar dataKey="scans" fill="#10b981" radius={[4, 4, 0, 0]} barSize={40}>
                                    {trends.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fillOpacity={0.8} />
                                    ))}
                                </Bar>
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </section>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="p-6 rounded-2xl bg-white/5 border border-white/10">
                    <AlertCircle className="text-primary mb-3" size={24} />
                    <h4 className="font-bold text-white">Mean Time to Discovery</h4>
                    <p className="text-2xl font-black text-white mt-1">4.2m</p>
                    <p className="text-[10px] text-muted-foreground mt-1">Average worker processing time.</p>
                </div>
                <div className="p-6 rounded-2xl bg-white/5 border border-white/10">
                    <Shield className="text-emerald-500 mb-3" size={24} />
                    <h4 className="font-bold text-white">Remediation Rate</h4>
                    <p className="text-2xl font-black text-white mt-1">68%</p>
                    <p className="text-[10px] text-muted-foreground mt-1">Findings marked as 'Fixed' in Git.</p>
                </div>
                <div className="p-6 rounded-2xl bg-white/5 border border-white/10">
                    <Zap className="text-purple-500 mb-3" size={24} />
                    <h4 className="font-bold text-white">AI Reasoning Accuracy</h4>
                    <p className="text-2xl font-black text-white mt-1">94%</p>
                    <p className="text-[10px] text-muted-foreground mt-1">User confidence feedback score.</p>
                </div>
            </div>
        </div>
    );
}
