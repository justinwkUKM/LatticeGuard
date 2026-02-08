'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
    Search,
    Filter,
    Calendar,
    ArrowRight,
    Shield,
    Box,
    ExternalLink,
    ChevronRight
} from 'lucide-react';
import Link from 'next/link';
import { cn } from '@/lib/utils';
import { fetchScans } from '@/lib/api';

export default function HistoryPage() {
    const [scans, setScans] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');

    useEffect(() => {
        async function loadScans() {
            try {
                const data = await fetchScans();
                // Assuming data.scans is a list of run_id strings for now based on previous knowledge
                // But the dashboard also treats them as objects if they were more rich.
                // Let's normalize data.
                const normalizedScans = (data.scans || []).map((scan: any) => {
                    if (typeof scan === 'string') {
                        return {
                            id: scan,
                            repository: scan.split('/').pop() || scan,
                            date: new Date().toLocaleDateString(), // Placeholder if date not provided
                            status: 'Completed',
                            riskLevel: 'Unknown'
                        };
                    }
                    return scan;
                });
                setScans(normalizedScans);
            } catch (err) {
                console.error('Failed to load scan history:', err);
            } finally {
                setLoading(false);
            }
        }
        loadScans();
    }, []);

    const filteredScans = scans.filter(scan =>
        scan.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        scan.repository.toLowerCase().includes(searchTerm.toLowerCase())
    );

    return (
        <div className="space-y-8 max-w-7xl mx-auto pb-20">
            <header className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                    <h1 className="text-3xl font-extrabold text-white tracking-tight">Scan History</h1>
                    <p className="text-muted-foreground mt-1">Audit log of all repository and infrastructure assessments.</p>
                </div>

                <div className="flex items-center gap-3">
                    <div className="relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" size={18} />
                        <input
                            type="text"
                            placeholder="Search history..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="pl-10 pr-4 py-2 bg-white/5 border border-white/10 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 w-64 transition-all"
                        />
                    </div>
                    <button className="p-2 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 transition-colors">
                        <Filter size={20} />
                    </button>
                </div>
            </header>

            <section>
                {loading ? (
                    <div className="grid grid-cols-1 gap-4">
                        {[1, 2, 3].map(i => (
                            <div key={i} className="h-24 rounded-2xl bg-white/5 animate-pulse" />
                        ))}
                    </div>
                ) : filteredScans.length > 0 ? (
                    <div className="grid grid-cols-1 gap-4">
                        {filteredScans.map((scan, index) => (
                            <motion.div
                                key={scan.id}
                                initial={{ opacity: 0, x: -20 }}
                                animate={{ opacity: 1, x: 0 }}
                                transition={{ delay: index * 0.05 }}
                                className="group relative overflow-hidden rounded-2xl glass border border-white/5 hover:border-primary/30 transition-all p-5"
                            >
                                <Link href={`/history/${scan.id}`} className="flex items-center justify-between">
                                    <div className="flex items-center gap-5">
                                        <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center text-primary group-hover:scale-110 transition-transform">
                                            <Box size={24} />
                                        </div>
                                        <div>
                                            <h3 className="text-lg font-bold text-white group-hover:text-primary transition-colors">
                                                {scan.repository}
                                            </h3>
                                            <div className="flex items-center gap-4 mt-1 text-sm text-muted-foreground">
                                                <span className="flex items-center gap-1">
                                                    <Calendar size={14} />
                                                    {scan.date}
                                                </span>
                                                <span className="flex items-center gap-1 capitalize">
                                                    <span className={`w-2 h-2 rounded-full ${scan.riskLevel === 'Critical' ? 'bg-destructive' :
                                                        scan.riskLevel === 'High' ? 'bg-orange-500' :
                                                            'bg-emerald-500'
                                                        }`} />
                                                    {scan.riskLevel} Risk
                                                </span>
                                                <span className={cn(
                                                    "px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wider",
                                                    scan.id.startsWith('node-') ? "bg-purple-500/10 text-purple-500" :
                                                        (scan.id.includes('http') || scan.repository.includes('github')) ? "bg-blue-500/10 text-blue-500" :
                                                            "bg-emerald-500/10 text-emerald-500"
                                                )}>
                                                    {scan.id.startsWith('node-') ? 'Network' :
                                                        (scan.id.includes('http') || scan.repository.includes('github')) ? 'Remote' : 'Local'}
                                                </span>
                                                <span className="px-2 py-0.5 rounded-md bg-white/5 text-[10px] font-mono">
                                                    ID: {scan.id.substring(0, 8)}...
                                                </span>
                                            </div>
                                        </div>
                                    </div>

                                    <div className="flex items-center gap-4">
                                        <div className="text-right hidden sm:block">
                                            <div className="text-sm font-medium text-white">{scan.status}</div>
                                            <div className="text-xs text-muted-foreground">View Detailed Metrics</div>
                                        </div>
                                        <div className="w-10 h-10 rounded-full bg-white/5 flex items-center justify-center group-hover:bg-primary group-hover:text-primary-foreground transition-all">
                                            <ChevronRight size={20} />
                                        </div>
                                    </div>
                                </Link>
                            </motion.div>
                        ))}
                    </div>
                ) : (
                    <div className="text-center py-20 glass rounded-3xl">
                        <div className="bg-white/5 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4 text-muted-foreground">
                            <Search size={32} />
                        </div>
                        <h3 className="text-xl font-bold text-white">No scans found</h3>
                        <p className="text-muted-foreground mt-2 max-w-md mx-auto">
                            We couldn't find any scans matching your criteria. Start a new assessment to see it here.
                        </p>
                        <Link
                            href="/assessments"
                            className="inline-flex items-center gap-2 mt-6 px-6 py-2 rounded-xl bg-primary text-primary-foreground font-bold quantum-glow hover:opacity-90 transition-opacity"
                        >
                            Start First Scan
                        </Link>
                    </div>
                )}
            </section>
        </div>
    );
}
