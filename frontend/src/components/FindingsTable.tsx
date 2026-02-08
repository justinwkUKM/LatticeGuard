'use client';

import { ShieldAlert, Info, AlertTriangle, ExternalLink } from 'lucide-react';
import { motion } from 'framer-motion';

export type Finding = {
    id: string;
    path: string;
    line: number;
    name: string;
    category: string;
    algorithm?: string;
    is_pqc_vulnerable: boolean;
    risk_level: 'critical' | 'high' | 'medium' | 'low' | 'safe';
    description: string;
    status: 'Open' | 'Resolved' | 'Ignored';
};

interface FindingsTableProps {
    findings: Finding[];
    onSelectFinding: (finding: Finding) => void;
}

export function FindingsTable({ findings, onSelectFinding }: FindingsTableProps) {
    return (
        <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
                <thead>
                    <tr className="border-b border-white/5 text-[10px] uppercase tracking-widest text-muted-foreground font-bold">
                        <th className="px-6 py-4">Risk</th>
                        <th className="px-6 py-4">Asset / Algorithm</th>
                        <th className="px-6 py-4">Category</th>
                        <th className="px-6 py-4">Status</th>
                        <th className="px-6 py-4">Location</th>
                        <th className="px-6 py-4 text-right">Action</th>
                    </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                    {findings.map((finding, index) => (
                        <motion.tr
                            key={finding.id}
                            initial={{ opacity: 0, x: -10 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ delay: index * 0.05 }}
                            className="group hover:bg-white/[0.02] transition-colors cursor-pointer"
                            onClick={() => onSelectFinding(finding)}
                        >
                            <td className="px-6 py-4">
                                <div className="flex items-center gap-2">
                                    {finding.risk_level === 'critical' && <ShieldAlert className="text-destructive w-4 h-4" />}
                                    {finding.risk_level === 'high' && <AlertTriangle className="text-amber-500 w-4 h-4" />}
                                    {finding.risk_level === 'medium' && <AlertTriangle className="text-secondary w-4 h-4" />}
                                    {finding.risk_level === 'low' && <Info className="text-primary w-4 h-4" />}
                                    <span className={cn(
                                        "text-[10px] font-bold uppercase tracking-wider",
                                        finding.risk_level === 'critical' && "text-destructive",
                                        finding.risk_level === 'high' && "text-amber-500",
                                        finding.risk_level === 'medium' && "text-secondary",
                                        finding.risk_level === 'low' && "text-primary",
                                        finding.risk_level === 'safe' && "text-emerald-500",
                                    )}>
                                        {finding.risk_level}
                                    </span>
                                </div>
                            </td>
                            <td className="px-6 py-4">
                                <div className="flex flex-col">
                                    <span className="text-sm font-semibold text-white">{finding.name}</span>
                                    <span className="text-[10px] text-muted-foreground font-mono">{finding.algorithm || 'Unknown'}</span>
                                </div>
                            </td>
                            <td className="px-6 py-4">
                                <span className="px-2 py-0.5 rounded-full bg-white/5 border border-white/10 text-[10px] text-white/50">
                                    {finding.category}
                                </span>
                            </td>
                            <td className="px-6 py-4">
                                <div className={cn(
                                    "text-[9px] font-black uppercase tracking-tighter px-2 py-0.5 rounded-md w-fit border",
                                    finding.status === 'Open' ? "bg-destructive/10 text-destructive border-destructive/20" :
                                        finding.status === 'Resolved' ? "bg-emerald-500/10 text-emerald-500 border-emerald-500/20" :
                                            "bg-white/5 text-muted-foreground border-white/10"
                                )}>
                                    {finding.status}
                                </div>
                            </td>
                            <td className="px-6 py-4">
                                <div className="flex flex-col">
                                    <span className="text-xs text-white/70 max-w-[200px] truncate">{finding.path.split('/').pop()}</span>
                                    <span className="text-[10px] text-muted-foreground">Line {finding.line}</span>
                                </div>
                            </td>
                            <td className="px-6 py-4 text-right">
                                <button className="p-2 rounded-lg bg-white/5 border border-white/10 text-white/50 group-hover:text-primary group-hover:border-primary/30 transition-all">
                                    <ExternalLink size={14} />
                                </button>
                            </td>
                        </motion.tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

function cn(...inputs: any[]) {
    return inputs.filter(Boolean).join(' ');
}
