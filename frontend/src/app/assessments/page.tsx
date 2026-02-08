'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Plus,
    Github,
    Globe,
    ShieldCheck,
    Zap,
    Search,
    ArrowRight,
    Info,
    Activity,
    AlertTriangle
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { triggerScan, triggerNodeScan } from '@/lib/api';
import Link from 'next/link';

export default function AssessmentsPage() {
    const router = useRouter();
    const [scanType, setScanType] = useState<'repo' | 'network'>('repo');
    const [inputValue, setInputValue] = useState('');
    const [port, setPort] = useState('443');
    const [strategy, setStrategy] = useState<'fast' | 'deep'>('fast');
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [jobId, setJobId] = useState<string | null>(null);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsSubmitting(true);
        setJobId(null);
        setError(null);

        try {
            let result;
            if (scanType === 'repo') {
                result = await triggerScan(inputValue);
            } else {
                result = await triggerNodeScan(inputValue, parseInt(port) || 443);
            }
            setJobId(result.job_id);
            // Auto-redirect to scan detail page
            router.push(`/history/${result.job_id}`);
        } catch (err: any) {
            console.error('Failed to trigger scan:', err);
            setError(err.message || 'Failed to deploy assessment. Please check system status.');
        } finally {
            setIsSubmitting(false);
        }
    };

    return (
        <div className="max-w-4xl mx-auto pb-20">
            <header className="mb-10">
                <h1 className="text-3xl font-extrabold text-white tracking-tight">New Assessment</h1>
                <p className="text-muted-foreground mt-1">Initiate a Post-Quantum risk discovery across your ecosystem.</p>
            </header>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <div className="lg:col-span-2 space-y-6">
                    <section className="glass rounded-3xl p-8 border border-white/5">
                        <div className="flex p-1 bg-white/5 rounded-2xl mb-8">
                            <button
                                onClick={() => setScanType('repo')}
                                className={cn(
                                    "flex-1 flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-bold transition-all",
                                    scanType === 'repo' ? "bg-primary text-primary-foreground shadow-lg" : "text-muted-foreground hover:text-white"
                                )}
                            >
                                <Github size={18} />
                                Repository Scan
                            </button>
                            <button
                                onClick={() => setScanType('network')}
                                className={cn(
                                    "flex-1 flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-bold transition-all",
                                    scanType === 'network' ? "bg-primary text-primary-foreground shadow-lg" : "text-muted-foreground hover:text-white"
                                )}
                            >
                                <Globe size={18} />
                                Network Node
                            </button>
                        </div>

                        <form onSubmit={handleSubmit} className="space-y-6">
                            <div>
                                <label className="block text-sm font-medium text-muted-foreground mb-2">
                                    {scanType === 'repo' ? 'Repository URL' : 'Target URL / Host IP'}
                                </label>
                                <div className="relative">
                                    <div className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground">
                                        <Search size={18} />
                                    </div>
                                    <input
                                        type="text"
                                        required
                                        placeholder={scanType === 'repo' ? "https://github.com/org/repo" : "192.168.1.1 or api.example.com"}
                                        value={inputValue}
                                        onChange={(e) => setInputValue(e.target.value)}
                                        className="w-full pl-12 pr-4 py-4 bg-white/5 border border-white/10 rounded-2xl text-white placeholder:text-muted-foreground/30 focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all font-mono"
                                    />
                                </div>
                            </div>

                            {scanType === 'network' && (
                                <motion.div
                                    initial={{ opacity: 0, height: 0 }}
                                    animate={{ opacity: 1, height: 'auto' }}
                                    className="space-y-2"
                                >
                                    <label className="block text-sm font-medium text-muted-foreground mb-2">Target Port</label>
                                    <input
                                        type="number"
                                        required
                                        value={port}
                                        onChange={(e) => setPort(e.target.value)}
                                        className="w-32 px-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all font-mono"
                                    />
                                </motion.div>
                            )}

                            <div className="grid grid-cols-2 gap-4">
                                <button
                                    type="button"
                                    onClick={() => setStrategy('fast')}
                                    className={cn(
                                        "p-4 rounded-2xl border transition-all text-left group",
                                        strategy === 'fast' ? "bg-white/5 border-primary" : "bg-transparent border-white/10 hover:border-white/20"
                                    )}
                                >
                                    <div className={cn(
                                        "w-10 h-10 rounded-xl flex items-center justify-center mb-3 transition-colors",
                                        strategy === 'fast' ? "bg-primary text-primary-foreground" : "bg-white/5 text-muted-foreground group-hover:text-white"
                                    )}>
                                        <Zap size={20} />
                                    </div>
                                    <div className="font-bold text-white">Fast Discovery</div>
                                    <div className="text-xs text-muted-foreground mt-1">Deterministic regex-based scanning.</div>
                                </button>

                                <button
                                    type="button"
                                    onClick={() => setStrategy('deep')}
                                    className={cn(
                                        "p-4 rounded-2xl border transition-all text-left group",
                                        strategy === 'deep' ? "bg-white/5 border-purple-500" : "bg-transparent border-white/10 hover:border-white/20"
                                    )}
                                >
                                    <div className={cn(
                                        "w-10 h-10 rounded-xl flex items-center justify-center mb-3 transition-colors",
                                        strategy === 'deep' ? "bg-purple-500 text-white" : "bg-white/5 text-muted-foreground group-hover:text-white"
                                    )}>
                                        <ShieldCheck size={20} />
                                    </div>
                                    <div className="font-bold text-white">Deep Core Scan</div>
                                    <div className="text-xs text-muted-foreground mt-1">AI-augmented threat reasoning.</div>
                                </button>
                            </div>

                            <button
                                type="submit"
                                disabled={isSubmitting}
                                className={cn(
                                    "w-full py-4 rounded-2xl font-black text-lg transition-all flex items-center justify-center gap-3",
                                    "bg-primary text-primary-foreground quantum-glow hover:opacity-90 active:scale-[0.98] disabled:opacity-50"
                                )}
                            >
                                {isSubmitting ? (
                                    <Activity className="animate-spin" size={24} />
                                ) : (
                                    <>
                                        <Zap size={24} />
                                        Deploy Assessment
                                        <ArrowRight size={20} />
                                    </>
                                )}
                            </button>
                        </form>
                    </section>

                    <AnimatePresence>
                        {error && (
                            <motion.div
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -10 }}
                                className="p-6 rounded-3xl bg-destructive/10 border border-destructive/20 text-destructive flex items-start gap-4"
                            >
                                <div className="mt-1"><AlertTriangle size={20} /></div>
                                <div>
                                    <h4 className="font-bold">Assessment Failed</h4>
                                    <p className="text-sm opacity-80 mt-1">
                                        {error}
                                    </p>
                                    <button
                                        onClick={() => setError(null)}
                                        className="mt-3 text-xs font-bold underline"
                                    >
                                        Dismiss
                                    </button>
                                </div>
                            </motion.div>
                        )}
                    </AnimatePresence>
                </div>

                <div className="space-y-6">
                    <div className="glass rounded-3xl p-6 border border-white/5">
                        <h4 className="text-white font-bold mb-4 flex items-center gap-2">
                            <ShieldCheck className="text-primary" size={20} />
                            Policy Guidance
                        </h4>
                        <ul className="space-y-4 text-sm text-muted-foreground">
                            <li className="flex gap-3">
                                <div className="w-1.5 h-1.5 rounded-full bg-primary mt-1.5 shrink-0" />
                                Only scan assets you are authorized to audit.
                            </li>
                            <li className="flex gap-3">
                                <div className="w-1.5 h-1.5 rounded-full bg-primary mt-1.5 shrink-0" />
                                "Deep Core Scan" utilizes LLM tokens and may take longer to complete.
                            </li>
                            <li className="flex gap-3">
                                <div className="w-1.5 h-1.5 rounded-full bg-primary mt-1.5 shrink-0" />
                                Network scans should target specific endpoints rather than wide CIDR blocks for optimal accuracy.
                            </li>
                        </ul>
                    </div>

                    <div className="bg-gradient-to-br from-indigo-600 to-purple-700 rounded-3xl p-6 shadow-xl relative overflow-hidden group">
                        <div className="absolute -right-8 -bottom-8 opacity-20 group-hover:scale-125 transition-transform">
                            <Zap size={120} />
                        </div>
                        <h4 className="text-white font-black text-xl mb-2">Pro Tip</h4>
                        <p className="text-white/80 text-sm leading-relaxed">
                            Connect your GitHub Organization settings to automatically discover newly created repositories and flag PQC debt at the PR stage.
                        </p>
                        <button className="mt-4 text-xs font-bold text-white underline underline-offset-4 decoration-2">
                            Configure Webhooks
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}
