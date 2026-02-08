'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
    ChevronLeft,
    Download,
    GitBranch,
    Clock,
    Database,
    Search,
    CheckCircle2,
    Zap,
    ShieldAlert,
    Activity,
    Loader2,
    Network
} from 'lucide-react';
import Link from 'next/link';
import { FindingsTable, Finding } from '@/components/FindingsTable';
import { CodePreview } from '@/components/CodePreview';
import { LogViewer } from '@/components/LogViewer';
import { fetchScanDetails, updateFinding, fetchJobStatus } from '@/lib/api';
import { cn } from '@/lib/utils';

export default function ScanDetailPage({ params }: { params: { id: string } }) {
    const [activeTab, setActiveTab] = useState<'findings' | 'analysis'>('findings');
    const [selectedFinding, setSelectedFinding] = useState<any | null>(null);
    const [findings, setFindings] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [updating, setUpdating] = useState<string | null>(null);

    // Live job status
    const [jobStatus, setJobStatus] = useState<any>(null);
    const [progress, setProgress] = useState(0);
    const [isComplete, setIsComplete] = useState(false);

    // Poll for job status
    useEffect(() => {
        let interval: NodeJS.Timeout;

        async function pollStatus() {
            try {
                const status = await fetchJobStatus(params.id);
                setJobStatus(status);
                setProgress(parseInt(status.progress || '0'));

                if (status.status === 'completed') {
                    setIsComplete(true);
                    clearInterval(interval);
                    // Fetch final scan details
                    loadFindings();
                } else if (status.status === 'failed') {
                    setIsComplete(true);
                    clearInterval(interval);
                }
            } catch (err) {
                console.error('Failed to fetch job status:', err);
            }
        }

        async function loadFindings() {
            try {
                const data = await fetchScanDetails(params.id);
                setFindings(data.findings || []);
            } catch (err) {
                console.error('Failed to load scan details:', err);
            } finally {
                setLoading(false);
            }
        }

        // Initial load
        pollStatus();
        interval = setInterval(pollStatus, 2000);

        return () => clearInterval(interval);
    }, [params.id]);

    const handleUpdateStatus = async (findingId: string, status: string) => {
        setUpdating(findingId);
        try {
            await updateFinding(findingId, status);
            setFindings(prev => prev.map(f => f.id === findingId ? { ...f, status } : f));
            if (selectedFinding?.id === findingId) {
                setSelectedFinding({ ...selectedFinding, status });
            }
        } catch (err) {
            console.error('Update failed:', err);
        } finally {
            setUpdating(null);
        }
    };

    const mockCode = `import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_unsafe_key():
    # CRITICAL: RSA-2048 is no longer quantum resistant
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key`;

    const repoName = jobStatus?.repo_path?.split('/').pop() || params.id;
    const scanStatus = jobStatus?.status || 'queued';
    const totalFiles = jobStatus?.total_files || 0;
    const completedFiles = jobStatus?.completed_files || 0;

    return (
        <div className="space-y-8 max-w-7xl mx-auto pb-20">
            {/* Header */}
            <section>
                <Link
                    href="/"
                    className="flex items-center gap-2 text-muted-foreground hover:text-white transition-colors mb-6 group w-fit"
                >
                    <ChevronLeft size={16} className="transition-transform group-hover:-translate-x-1" />
                    <span className="text-xs font-bold uppercase tracking-wider">Back to Dashboard</span>
                </Link>

                <div className="flex items-center justify-between">
                    <div className="space-y-1">
                        <h1 className="text-3xl font-extrabold text-white tracking-tight">Scan: {params.id}</h1>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground">
                            <div className="flex items-center gap-1.5">
                                <Database size={14} />
                                <span>Target: {repoName}</span>
                            </div>
                            {jobStatus?.repo_path && (
                                <div className="flex items-center gap-1.5">
                                    <GitBranch size={14} />
                                    <span className="truncate max-w-[200px]">{jobStatus.repo_path}</span>
                                </div>
                            )}
                        </div>
                    </div>
                    <div className="flex gap-3">
                        {isComplete && (
                            <>
                                <Link
                                    href={`/blast-radius/${params.id}`}
                                    className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-purple-500/20 to-pink-500/20 border border-purple-500/30 text-sm font-semibold text-white hover:border-purple-400/50 transition-colors"
                                >
                                    <Network size={16} />
                                    Blast Radius
                                </Link>
                                <button className="flex items-center gap-2 px-4 py-2 rounded-lg bg-white/5 border border-white/10 text-sm font-semibold text-white hover:bg-white/10 transition-colors">
                                    <Download size={16} />
                                    JSON Report
                                </button>
                            </>
                        )}
                    </div>
                </div>
            </section>

            {/* Live Progress Banner (when scanning) */}
            {!isComplete && (
                <motion.section
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="glass rounded-2xl p-6 border border-primary/20"
                >
                    <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center gap-3">
                            <Loader2 className="text-primary animate-spin" size={20} />
                            <div>
                                <h3 className="text-white font-bold">Scan In Progress</h3>
                                <p className="text-xs text-muted-foreground">
                                    Status: <span className="text-primary font-mono">{scanStatus}</span>
                                    {totalFiles > 0 && ` • ${completedFiles}/${totalFiles} files analyzed`}
                                </p>
                            </div>
                        </div>
                        <span className="text-2xl font-black text-primary">{progress}%</span>
                    </div>
                    <div className="h-2 bg-white/10 rounded-full overflow-hidden">
                        <motion.div
                            className="h-full bg-primary shadow-[0_0_15px_rgba(34,211,238,0.6)]"
                            initial={{ width: 0 }}
                            animate={{ width: `${progress}%` }}
                            transition={{ type: 'spring', stiffness: 50 }}
                        />
                    </div>
                </motion.section>
            )}

            {/* Summary Row (only show when complete) */}
            {isComplete && (
                <section className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="p-6 rounded-2xl glass flex items-center justify-between">
                        <div>
                            <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest mb-1">Status</p>
                            <div className={cn(
                                "flex items-center gap-2",
                                scanStatus === 'completed' ? "text-emerald-500" : "text-destructive"
                            )}>
                                {scanStatus === 'completed' ? <CheckCircle2 size={18} /> : <ShieldAlert size={18} />}
                                <h3 className="text-lg font-bold">
                                    {scanStatus === 'completed' ? 'Analysis Complete' : 'Scan Failed'}
                                </h3>
                            </div>
                        </div>
                        <div className="h-10 w-[1px] bg-white/5" />
                        <div className="text-right">
                            <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest mb-1">Files Analyzed</p>
                            <h3 className="text-2xl font-black text-primary">{totalFiles}</h3>
                        </div>
                    </div>

                    <div className="flex items-center gap-4 p-6 rounded-2xl glass">
                        <div className="w-12 h-12 rounded-xl bg-destructive/10 flex items-center justify-center text-destructive">
                            <ShieldAlert size={24} />
                        </div>
                        <div>
                            <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest">PQC Risks</p>
                            <h3 className="text-xl font-black text-white">
                                {loading ? '...' : findings.filter(f => f.is_pqc && f.status === 'Open').length} Open
                            </h3>
                        </div>
                    </div>

                    <div className="flex items-center gap-4 p-6 rounded-2xl glass">
                        <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center text-primary">
                            <Search size={24} />
                        </div>
                        <div>
                            <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest">Resolved</p>
                            <h3 className="text-xl font-black text-white">
                                {loading ? '...' : findings.filter(f => f.status === 'Resolved').length}
                            </h3>
                        </div>
                    </div>
                </section>
            )}

            {/* Content Area */}
            <section className="flex flex-col lg:flex-row gap-6 h-[700px]">
                <div className="flex-1 glass rounded-2xl overflow-hidden flex flex-col">
                    <div className="border-b border-white/5 flex items-center px-8 h-14 gap-8">
                        <button
                            onClick={() => setActiveTab('findings')}
                            className={cn(
                                "text-xs font-bold uppercase tracking-widest h-full relative transition-colors",
                                activeTab === 'findings' ? "text-primary border-b-2 border-primary" : "text-muted-foreground hover:text-white"
                            )}
                        >
                            Vulnerability Inventory
                        </button>
                        <button
                            onClick={() => setActiveTab('analysis')}
                            className={cn(
                                "text-xs font-bold uppercase tracking-widest h-full relative transition-colors",
                                activeTab === 'analysis' ? "text-primary border-b-2 border-primary" : "text-muted-foreground hover:text-white"
                            )}
                        >
                            AI Insight Log
                        </button>
                    </div>

                    <div className="flex-1 overflow-auto">
                        {activeTab === 'findings' ? (
                            !isComplete ? (
                                <div className="p-20 flex flex-col items-center justify-center text-center opacity-40 h-full">
                                    <Activity size={48} className="mb-4 text-primary animate-spin" />
                                    <p className="text-sm font-medium">Scan in progress...</p>
                                    <p className="text-xs text-muted-foreground mt-2">Findings will appear here once analysis is complete.</p>
                                </div>
                            ) : loading ? (
                                <div className="p-20 flex flex-col items-center justify-center text-center opacity-40 h-full">
                                    <Activity size={48} className="mb-4 text-primary animate-spin" />
                                    <p className="text-sm font-medium">Loading findings...</p>
                                </div>
                            ) : findings.length === 0 ? (
                                <div className="p-20 flex flex-col items-center justify-center text-center opacity-40 h-full">
                                    <CheckCircle2 size={48} className="mb-4 text-emerald-500" />
                                    <p className="text-sm font-medium text-emerald-500">No PQC vulnerabilities found!</p>
                                    <p className="text-xs text-muted-foreground mt-2">This repository appears to be quantum-safe.</p>
                                </div>
                            ) : (
                                <FindingsTable
                                    findings={findings}
                                    onSelectFinding={(f) => setSelectedFinding(f)}
                                />
                            )
                        ) : (
                            <LogViewer runId={params.id} />
                        )}
                    </div>
                </div>

                <div className="w-full lg:w-[450px] shrink-0">
                    {selectedFinding ? (
                        <div className="h-full flex flex-col gap-6">
                            <CodePreview
                                code={mockCode}
                                language="python"
                                filePath={selectedFinding.path}
                                highlightLine={selectedFinding.line % 10 + 5}
                            />
                            <div className="glass p-6 rounded-2xl space-y-4">
                                <div>
                                    <h4 className="text-sm font-bold text-white mb-2 uppercase tracking-wide">Remediation</h4>
                                    <p className="text-xs text-muted-foreground leading-relaxed">
                                        {selectedFinding.description || 'Migrate to a Lattice-based scheme like Kyber-768 for key encapsulation or Dilithium for signatures.'}
                                    </p>
                                </div>

                                <div className="pt-4 border-t border-white/5 flex gap-2">
                                    {selectedFinding.status === 'Open' ? (
                                        <>
                                            <button
                                                onClick={() => handleUpdateStatus(selectedFinding.id, 'Resolved')}
                                                disabled={updating === selectedFinding.id}
                                                className="flex-1 py-3 px-4 rounded-xl bg-emerald-500/10 text-emerald-500 text-[10px] font-bold uppercase tracking-wider hover:bg-emerald-500/20 transition-all border border-emerald-500/20"
                                            >
                                                Mark Resolved
                                            </button>
                                            <button
                                                onClick={() => handleUpdateStatus(selectedFinding.id, 'Ignored')}
                                                disabled={updating === selectedFinding.id}
                                                className="flex-1 py-3 px-4 rounded-xl bg-white/5 text-muted-foreground text-[10px] font-bold uppercase tracking-wider hover:bg-white/10 transition-all border border-white/10"
                                            >
                                                Ignore
                                            </button>
                                        </>
                                    ) : (
                                        <div className={cn(
                                            "w-full py-3 px-4 rounded-xl text-center text-[10px] font-bold uppercase tracking-widest border",
                                            selectedFinding.status === 'Resolved' ? "bg-emerald-500/10 text-emerald-500 border-emerald-500/20" : "bg-white/5 text-muted-foreground border-white/10"
                                        )}>
                                            Status: {selectedFinding.status}
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="h-full flex items-center justify-center glass rounded-2xl border-dashed border-white/5 text-muted-foreground/30 text-xs font-bold uppercase tracking-widest text-center px-10">
                            Select a finding to inspect vulnerable code snippet
                        </div>
                    )}
                </div>
            </section>
        </div>
    );
}
