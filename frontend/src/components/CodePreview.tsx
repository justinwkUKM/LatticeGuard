'use client';

import { motion } from 'framer-motion';
import { Terminal, Copy, ExternalLink } from 'lucide-react';

interface CodePreviewProps {
    code: string;
    language: string;
    filePath: string;
    highlightLine?: number;
}

export function CodePreview({ code, language, filePath, highlightLine }: CodePreviewProps) {
    const lines = code.split('\n');

    return (
        <div className="rounded-2xl border border-white/10 glass overflow-hidden flex flex-col h-full font-mono">
            <div className="h-12 bg-white/5 border-b border-white/5 flex items-center justify-between px-6 shrink-0">
                <div className="flex items-center gap-2">
                    <Terminal size={14} className="text-primary" />
                    <span className="text-[11px] font-bold text-white/70 tracking-tight">{filePath}</span>
                </div>
                <div className="flex gap-4">
                    <button className="text-white/30 hover:text-white transition-colors">
                        <Copy size={14} />
                    </button>
                    <button className="text-white/30 hover:text-white transition-colors">
                        <ExternalLink size={14} />
                    </button>
                </div>
            </div>
            <div className="flex-1 overflow-auto p-6 text-xs leading-relaxed custom-scrollbar">
                <table className="w-full border-collapse">
                    <tbody>
                        {lines.map((line, i) => {
                            const lineNum = i + 1;
                            const isHighlighted = lineNum === highlightLine;
                            return (
                                <tr
                                    key={i}
                                    className={isHighlighted ? "bg-primary/10 -mx-6 px-6 block w-full border-l-2 border-primary" : ""}
                                >
                                    <td className="w-10 pr-6 text-white/20 text-right select-none">{lineNum}</td>
                                    <td className={cn(
                                        "whitespace-pre",
                                        isHighlighted ? "text-primary font-bold" : "text-white/80"
                                    )}>
                                        {line}
                                    </td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

function cn(...inputs: any[]) {
    return inputs.filter(Boolean).join(' ');
}
