'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
    FileText,
    Download,
    ExternalLink,
    Search,
    Database,
    ShieldCheck,
    ChevronRight
} from 'lucide-react';
import { fetchScans, exportReport } from '@/lib/api';
import { cn } from '@/lib/utils';

export default function ReportsPage() {
    const [scans, setScans] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [exporting, setExporting] = useState<string | null>(null);

    useEffect(() => {
        async function loadScans() {
            try {
                const data = await fetchScans();
                setScans(data.scans || []);
            } catch (err) {
                console.error('Failed to load scans for reports:', err);
            } finally {
                setLoading(false);
            }
        }
        loadScans();
    }, []);

    const handleExport = async (runId: string, format: 'csv' | 'json') => {
        setExporting(`${runId}-${format}`);
        try {
            const data = await exportReport(runId, format);
            const blob = new Blob([format === 'json' ? JSON.stringify(data, null, 2) : data], {
                type: format === 'json' ? 'application/json' : 'text/csv'
            });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `LatticeGuard-Report-${runId}.${format}`;
            a.click();
            window.URL.revokeObjectURL(url);
        } catch (err) {
            console.error('Export failed:', err);
            alert('Failed to generate export. Please try again.');
        } finally {
            setExporting(null);
        }
    };

    return (
        <div className="space-y-8 max-w-7xl mx-auto pb-20">
            <header>
                <h1 className="text-3xl font-extrabold text-white tracking-tight">Compliance & Reporting</h1>
                <p className="text-muted-foreground mt-1">Export audit-ready cryptographic discovery data for internal or regulatory reviews.</p>
            </header>

            <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
                <aside className="space-y-6">
                    <div className="glass rounded-3xl p-6 border border-white/5 h-fit">
                        <h4 className="font-bold text-white mb-4">Export Preferences</h4>
                        <div className="space-y-4">
                            <div>
                                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Default Format</label>
                                <div className="grid grid-cols-2 gap-2 mt-2">
                                    <button className="px-3 py-2 rounded-xl bg-primary text-primary-foreground text-xs font-bold">JSON</button>
                                    <button className="px-3 py-2 rounded-xl bg-white/5 border border-white/10 text-xs font-bold text-white hover:bg-white/10">CSV</button>
                                </div>
                            </div>
                            <div className="pt-4 border-t border-white/5">
                                <p className="text-xs text-muted-foreground leading-relaxed italic">
                                    "JSON exports include raw AI reasoning metadata, while CSV provides a flattened inventory of cryptographic assets."
                                </p>
                            </div>
                        </div>
                    </div>

                    <div className="bg-gradient-to-br from-primary/20 to-secondary/20 rounded-3xl p-6 border border-white/10">
                        <ShieldCheck className="text-primary mb-3" size={24} />
                        <h4 className="font-bold text-white">Security Policy</h4>
                        <p className="text-xs text-muted-foreground mt-2 leading-relaxed">
                            LatticeGuard reports are sanitized to remove sensitive credentials but will include full file paths and algorithm identifiers.
                        </p>
                    </div>
                </aside>

                <section className="lg:col-span-3 space-y-4">
                    <div className="flex items-center justify-between mb-4">
                        <h3 className="font-bold text-white text-lg">Available Datasets</h3>
                        <div className="text-xs text-muted-foreground">Showing latest {scans.length} runs</div>
                    </div>

                    {loading ? (
                        <div className="space-y-4">
                            {[1, 2, 3].map(i => (
                                <div key={i} className="h-20 rounded-2xl bg-white/5 animate-pulse" />
                            ))}
                        </div>
                    ) : scans.length > 0 ? (
                        scans.map((runId) => (
                            <motion.div
                                key={runId}
                                initial={{ opacity: 0, scale: 0.98 }}
                                animate={{ opacity: 1, scale: 1 }}
                                className="group flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl glass border border-white/5 hover:border-primary/20 transition-all"
                            >
                                <div className="flex items-center gap-4">
                                    <div className="w-12 h-12 rounded-xl bg-white/5 flex items-center justify-center text-muted-foreground group-hover:bg-primary/10 group-hover:text-primary transition-colors">
                                        <Database size={24} />
                                    </div>
                                    <div>
                                        <h4 className="font-bold text-white text-sm sm:text-base truncate max-w-[200px] sm:max-w-none">
                                            {runId.startsWith('job-') || runId.startsWith('node-') ? `Scan: ${runId}` : runId}
                                        </h4>
                                        <p className="text-xs text-muted-foreground">Full snapshot of findings and assessments</p>
                                    </div>
                                </div>

                                <div className="flex items-center gap-2">
                                    <button
                                        onClick={() => handleExport(runId, 'json')}
                                        disabled={exporting === `${runId}-json`}
                                        className="flex-1 sm:flex-none flex items-center justify-center gap-2 px-4 py-2 rounded-xl bg-white/5 border border-white/10 text-xs font-bold text-white hover:bg-white/10 transition-colors disabled:opacity-50"
                                    >
                                        {exporting === `${runId}-json` ? '...' : <><Download size={14} /> JSON</>}
                                    </button>
                                    <button
                                        onClick={() => handleExport(runId, 'csv')}
                                        disabled={exporting === `${runId}-csv`}
                                        className="flex-1 sm:flex-none flex items-center justify-center gap-2 px-4 py-2 rounded-xl bg-white/5 border border-white/10 text-xs font-bold text-white hover:bg-white/10 transition-colors disabled:opacity-50"
                                    >
                                        {exporting === `${runId}-csv` ? '...' : <><Download size={14} /> CSV</>}
                                    </button>
                                    <button className="hidden sm:flex w-10 h-10 items-center justify-center rounded-xl bg-white/5 border border-white/10 hover:bg-primary hover:text-primary-foreground transition-all">
                                        <ChevronRight size={18} />
                                    </button>
                                </div>
                            </motion.div>
                        ))
                    ) : (
                        <div className="text-center py-20 glass rounded-3xl border border-dashed border-white/10">
                            <FileText className="mx-auto text-muted-foreground opacity-20 mb-4" size={48} />
                            <h4 className="text-white font-bold">No Data Available</h4>
                            <p className="text-sm text-muted-foreground max-w-xs mx-auto mt-2">
                                Perform your first system scan to generate audit reports and compliance data.
                            </p>
                        </div>
                    )}
                </section>
            </div>
        </div>
    );
}
