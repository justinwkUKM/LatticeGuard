'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { motion } from 'framer-motion';
import {
    LayoutDashboard,
    ShieldAlert,
    History,
    Settings,
    FileText,
    Activity
} from 'lucide-react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
    return twMerge(clsx(inputs));
}

const navItems = [
    { name: 'Dashboard', href: '/', icon: LayoutDashboard },
    { name: 'Assessments', href: '/assessments', icon: ShieldAlert },
    { name: 'Scan History', href: '/history', icon: History },
    { name: 'Reports', href: '/reports', icon: FileText },
    { name: 'Metrics', href: '/metrics', icon: Activity },
    { name: 'Settings', href: '/settings', icon: Settings },
];

export function Sidebar() {
    const pathname = usePathname();

    return (
        <div className="w-64 h-screen border-r border-white/10 glass flex flex-col p-4 fixed left-0 top-0">
            <div className="flex items-center gap-3 px-2 mb-10">
                <div className="w-10 h-10 rounded-xl bg-linear-to-br from-primary to-secondary flex items-center justify-center quantum-glow">
                    <ShieldAlert className="text-primary-foreground w-6 h-6" />
                </div>
                <div>
                    <h1 className="text-xl font-bold tracking-tight text-white">LatticeGuard</h1>
                    <p className="text-[10px] text-muted-foreground uppercase tracking-widest font-medium">PQC Assessment</p>
                </div>
            </div>

            <nav className="flex-1 space-y-1">
                {navItems.map((item) => {
                    const isActive = pathname === item.href;
                    return (
                        <Link
                            key={item.name}
                            href={item.href}
                            className={cn(
                                "flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200 group relative",
                                isActive
                                    ? "text-primary bg-primary/5"
                                    : "text-muted-foreground hover:text-white hover:bg-white/5"
                            )}
                        >
                            {isActive && (
                                <motion.div
                                    layoutId="active-nav"
                                    className="absolute left-0 w-1 h-6 bg-primary rounded-r-full"
                                />
                            )}
                            <item.icon className={cn(
                                "w-5 h-5 transition-colors",
                                isActive ? "text-primary" : "group-hover:text-primary/70"
                            )} />
                            <span className="font-medium">{item.name}</span>
                        </Link>
                    );
                })}
            </nav>

            <div className="mt-auto pt-6 border-t border-white/5">
                <div className="p-4 rounded-xl bg-linear-to-br from-primary/10 to-secondary/10 border border-white/5">
                    <p className="text-xs font-semibold text-primary mb-1">Queue Status</p>
                    <div className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                        <span className="text-xs text-muted-foreground">System Ready</span>
                    </div>
                </div>
            </div>
        </div>
    );
}
