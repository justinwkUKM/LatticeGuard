'use client';

import { useEffect, useRef, useState } from 'react';
import { fetchScanLogs } from '@/lib/api';
import { cn } from '@/lib/utils';
import { Activity, AlertTriangle, Bug, CheckCircle2, ChevronDown, Filter, Info, Terminal } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

interface LogEntry {
    level: string;
    component: string;
    message: string;
    timestamp: string;
}

interface LogViewerProps {
    runId: string;
    refreshInterval?: number;
    height?: string;
}

export function LogViewer({ runId, refreshInterval = 3000, height = "h-[600px]" }: LogViewerProps) {
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const [loading, setLoading] = useState(true);
    const [filterLevel, setFilterLevel] = useState<string | null>(null);
    const scrollRef = useRef<HTMLDivElement>(null);
    const [autoScroll, setAutoScroll] = useState(true);

    useEffect(() => {
        let interval: NodeJS.Timeout;

        const loadLogs = async () => {
            try {
                const data = await fetchScanLogs(runId);
                // Only update if we have new logs to avoid jitter
                setLogs(prev => {
                    if (data.length !== prev.length) return data;
                    return prev;
                });
            } catch (err) {
                console.error("Failed to load logs:", err);
            } finally {
                setLoading(false);
            }
        };

        loadLogs();
        if (refreshInterval > 0) {
            interval = setInterval(loadLogs, refreshInterval);
        }

        return () => clearInterval(interval);
    }, [runId, refreshInterval]);

    useEffect(() => {
        if (autoScroll && scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [logs, autoScroll]);

    const filteredLogs = filterLevel
        ? logs.filter(l => l.level === filterLevel)
        : logs;

    const getLevelIcon = (level: string) => {
        switch (level) {
            case 'ERROR': return <AlertTriangle size={14} className="text-destructive" />;
            case 'WARNING': return <Bug size={14} className="text-yellow-500" />;
            case 'SUCCESS': return <CheckCircle2 size={14} className="text-emerald-500" />;
            default: return <Info size={14} className="text-primary" />;
        }
    };

    const getLevelColor = (level: string) => {
        switch (level) {
            case 'ERROR': return 'text-destructive bg-destructive/10 border-destructive/20';
            case 'WARNING': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
            case 'SUCCESS': return 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20';
            default: return 'text-primary bg-primary/10 border-primary/20';
        }
    };

    return (
        <div className={cn("flex flex-col glass rounded-xl overflow-hidden", height)}>
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-white/5 bg-black/20">
                <div className="flex items-center gap-2">
                    <Terminal size={16} className="text-muted-foreground" />
                    <span className="text-xs font-bold uppercase tracking-widest text-muted-foreground">System Logs</span>
                    <span className="ml-2 px-2 py-0.5 rounded-full bg-white/5 text-[10px] text-white font-mono">
                        {logs.length} events
                    </span>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        onClick={() => setAutoScroll(!autoScroll)}
                        className={cn(
                            "p-1.5 rounded-md transition-colors",
                            autoScroll ? "text-primary bg-primary/10" : "text-muted-foreground hover:bg-white/5"
                        )}
                        title="Auto-scroll"
                    >
                        <ChevronDown size={14} />
                    </button>
                    <div className="h-4 w-[1px] bg-white/10" />
                    <div className="flex gap-1">
                        {['INFO', 'WARNING', 'ERROR'].map(level => (
                            <button
                                key={level}
                                onClick={() => setFilterLevel(filterLevel === level ? null : level)}
                                className={cn(
                                    "px-2 py-1 rounded-md text-[10px] font-bold transition-all border",
                                    filterLevel === level
                                        ? getLevelColor(level)
                                        : "text-muted-foreground border-transparent hover:bg-white/5"
                                )}
                            >
                                {level}
                            </button>
                        ))}
                    </div>
                </div>
            </div>

            {/* Log Stream */}
            <div
                ref={scrollRef}
                className="flex-1 overflow-y-auto p-4 space-y-2 font-mono text-xs scroll-smooth"
                onScroll={(e) => {
                    const target = e.target as HTMLDivElement;
                    const isBottom = Math.abs(target.scrollHeight - target.scrollTop - target.clientHeight) < 50;
                    if (!isBottom && autoScroll) setAutoScroll(false);
                    if (isBottom && !autoScroll) setAutoScroll(true);
                }}
            >
                {loading && logs.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-full text-muted-foreground/40 gap-2">
                        <Activity className="animate-pulse" size={24} />
                        <span>Connecting to worker stream...</span>
                    </div>
                ) : filteredLogs.length === 0 ? (
                    <div className="text-center py-20 text-muted-foreground/30 italic">No logs found matching criteria.</div>
                ) : (
                    <AnimatePresence initial={false}>
                        {filteredLogs.map((log, i) => (
                            <motion.div
                                key={i}
                                initial={{ opacity: 0, x: -10 }}
                                animate={{ opacity: 1, x: 0 }}
                                className="flex gap-3 group hover:bg-white/[0.02] p-1.5 -mx-1.5 rounded transition-colors"
                            >
                                <span className="text-muted-foreground/40 shrink-0 w-20 text-[10px] pt-0.5">
                                    {new Date(log.timestamp + "Z").toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                                </span>
                                <div className={cn("shrink-0 w-20 px-1.5 py-0.5 rounded text-[9px] font-bold text-center h-fit border", getLevelColor(log.level))}>
                                    {log.component}
                                </div>
                                <span className={cn("break-all leading-relaxed", log.level === 'ERROR' ? 'text-destructive' : 'text-slate-300')}>
                                    {log.message}
                                </span>
                            </motion.div>
                        ))}
                    </AnimatePresence>
                )}
            </div>
        </div>
    );
}
