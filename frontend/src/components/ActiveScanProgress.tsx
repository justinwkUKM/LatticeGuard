'use client';

import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { fetchAllJobs, fetchJobStatus, fetchScanLogs } from '@/lib/api';
import { cn } from '@/lib/utils';
import { Activity, Brain, CheckCircle2, FileSearch, Fingerprint, Loader2, Play, Search, ShieldCheck } from 'lucide-react';
import Link from 'next/link';

export function ActiveScanProgress() {
    const [activeJob, setActiveJob] = useState<any | null>(null);
    const [progress, setProgress] = useState(0);
    const [latestLog, setLatestLog] = useState<string>("Initializing...");
    const [status, setStatus] = useState<string>("idle");

    // Poll for active jobs
    useEffect(() => {
        const checkJobs = async () => {
            try {
                // First checks active jobs list
                const jobs = await fetchAllJobs();
                // Find first non-completed active job or the most recently completed one
                const running = jobs.find((j: any) => j.status.status !== 'completed' && j.status.status !== 'failed');

                if (running) {
                    setActiveJob(running);
                    updateJobState(running.run_id);
                } else if (jobs.length > 0) {
                    // If no running job, maybe show the last one if it completed recently (within 5 mins)?
                    // For now, just show nothing or the last running state if we had one.
                    if (activeJob && activeJob.status.status !== 'completed') {
                        // We were running, now we are done.
                        setStatus('completed');
                        setProgress(100);
                    }
                }
            } catch (err) {
                console.error("Failed to fetch jobs:", err);
            }
        };

        const updateJobState = async (runId: string) => {
            try {
                const statusData = await fetchJobStatus(runId);
                const logs = await fetchScanLogs(runId);

                setProgress(parseInt(statusData.progress || '0'));
                setStatus(statusData.status);

                if (logs && logs.length > 0) {
                    setLatestLog(logs[logs.length - 1].message);
                }
            } catch (e) {
                console.error(e);
            }
        };

        const interval = setInterval(checkJobs, 2000);
        checkJobs(); // Initial
        return () => clearInterval(interval);
    }, [activeJob]);

    // Show fallback UI if no active jobs and not just completed
    if (!activeJob && status !== 'completed') {
        return (
            <div className="w-full glass rounded-2xl p-8 mb-8 relative overflow-hidden border border-dashed border-white/10">
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                        <div className="w-12 h-12 rounded-xl bg-white/5 flex items-center justify-center text-muted-foreground">
                            <Activity size={24} />
                        </div>
                        <div>
                            <h3 className="text-lg font-bold text-white/50">No Active Scans</h3>
                            <p className="text-xs text-muted-foreground mt-1">Start a new assessment to see real-time progress here.</p>
                        </div>
                    </div>
                    <Link href="/assessments" className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-bold hover:opacity-90 transition-opacity">
                        <Play size={16} />
                        Start Scan
                    </Link>
                </div>
            </div>
        );
    }

    const steps = [
        { id: 1, label: "Discovery", icon: Search, range: [0, 10] },
        { id: 2, label: "Analysis", icon: FileSearch, range: [10, 40] },
        { id: 3, label: "Algorithm Check", icon: Fingerprint, range: [40, 80] },
        { id: 4, label: "Reporting", icon: ShieldCheck, range: [80, 100] }
    ];

    const currentStepIndex = steps.findIndex(s => progress < s.range[1]) === -1 ? 3 : steps.findIndex(s => progress < s.range[1]);

    return (
        <div className="w-full glass rounded-2xl p-8 mb-8 relative overflow-hidden group">
            <div className="absolute inset-0 bg-linear-to-r from-primary/5 via-transparent to-primary/5 opacity-50 pointer-events-none" />

            {/* Header */}
            <div className="flex items-center justify-between mb-8 relative z-10">
                <div className="flex items-center gap-4">
                    <div className="relative">
                        <div className="w-3 h-3 bg-primary rounded-full animate-ping absolute inset-0" />
                        <div className="w-3 h-3 bg-primary rounded-full relative" />
                    </div>
                    <div>
                        <h3 className="text-lg font-bold text-white tracking-wide uppercase">Real-Time Scan Progress</h3>
                        <p className="text-xs text-muted-foreground font-mono mt-1">
                            Job ID: <span className="text-primary">{activeJob?.run_id || 'Evaluating...'}</span> • Target: {activeJob?.status?.repo_path?.split('/').pop() || 'Unknown'}
                        </p>
                    </div>
                </div>
                {status === 'completed' ? (
                    <Link href={`/history/${activeJob?.run_id}`} className="flex items-center gap-2 px-4 py-2 bg-emerald-500/20 text-emerald-500 rounded-lg text-sm font-bold uppercase hover:bg-emerald-500/30 transition-colors">
                        View Report <CheckCircle2 size={16} />
                    </Link>
                ) : (
                    <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-black/40 border border-white/10 text-xs text-primary font-mono">
                        <Loader2 size={12} className="animate-spin" />
                        Scanning...
                    </div>
                )}
            </div>

            {/* Progress Bar */}
            <div className="relative h-1 bg-white/10 rounded-full mb-12">
                <motion.div
                    className="absolute top-0 left-0 h-full bg-primary shadow-[0_0_15px_rgba(34,211,238,0.6)] rounded-full"
                    initial={{ width: 0 }}
                    animate={{ width: `${progress}%` }}
                    transition={{ type: "spring", stiffness: 50 }}
                />

                {/* Steps */}
                <div className="absolute top-1/2 -translate-y-1/2 w-full flex justify-between px-[10%]">
                    {steps.map((step, i) => {
                        const isActive = i === currentStepIndex;
                        const isCompleted = i < currentStepIndex || status === 'completed';

                        return (
                            <div key={step.id} className="relative flex flex-col items-center group/step">
                                <div className={cn(
                                    "w-10 h-10 rounded-full flex items-center justify-center border-2 transition-all duration-500 z-10 relative bg-background",
                                    isActive ? "border-primary text-primary shadow-[0_0_20px_rgba(34,211,238,0.4)] scale-110" :
                                        isCompleted ? "border-primary bg-primary text-black" : "border-white/10 text-muted-foreground"
                                )}>
                                    <step.icon size={18} />

                                    {isActive && (
                                        <div className="absolute inset-0 rounded-full border-primary border-2 animate-ping opacity-20" />
                                    )}
                                </div>
                                <span className={cn(
                                    "absolute top-14 text-[10px] font-bold uppercase tracking-wider whitespace-nowrap transition-colors",
                                    isActive ? "text-primary" : isCompleted ? "text-white" : "text-muted-foreground"
                                )}>
                                    {step.id}. {step.label}
                                </span>
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* Live Log */}
            <div className="bg-black/30 rounded-xl p-4 font-mono text-xs border border-white/5 flex items-center justify-between">
                <div className="flex items-center gap-3 overflow-hidden">
                    <TerminalIcon className="text-muted-foreground shrink-0" size={14} />
                    <span className="text-primary truncate">
                        {status === 'completed' ? "Scan completed successfully. Results ready." : `> ${latestLog}`}
                    </span>
                </div>
                <div className="flex gap-1.5 shrink-0">
                    <div className="w-1.5 h-1.5 rounded-full bg-primary/50 animate-pulse" />
                    <div className="w-1.5 h-1.5 rounded-full bg-primary/50 animate-pulse delay-75" />
                    <div className="w-1.5 h-1.5 rounded-full bg-primary/50 animate-pulse delay-150" />
                </div>
            </div>

        </div>
    );
}

function TerminalIcon({ className, size }: { className?: string, size?: number }) {
    return (
        <svg
            xmlns="http://www.w3.org/2000/svg"
            width={size}
            height={size}
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            className={className}
        >
            <polyline points="4 17 10 11 4 5"></polyline>
            <line x1="12" y1="19" x2="20" y2="19"></line>
        </svg>
    )
}
