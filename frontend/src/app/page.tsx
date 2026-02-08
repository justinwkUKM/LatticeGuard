'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  ShieldAlert,
  Zap,
  Globe,
  Search,
  ArrowUpRight,
  TrendingDown,
  Lock,
  Box,
  Activity,
  Plus
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
  Cell
} from 'recharts';
import { fetchSummary, fetchScans, fetchAllJobs } from '@/lib/api';
import { cn } from '@/lib/utils';
import Link from 'next/link';

const chartData = [
  { name: 'Feb 1', risks: 400 },
  { name: 'Feb 2', risks: 300 },
  { name: 'Feb 3', risks: 200 },
  { name: 'Feb 4', risks: 278 },
  { name: 'Feb 5', risks: 189 },
  { name: 'Feb 6', risks: 239 },
  { name: 'Feb 7', risks: 349 },
];

const riskDist = [
  { name: 'Asymmetric', value: 45, color: '#22d3ee' },
  { name: 'Symmetric', value: 25, color: '#a855f7' },
  { name: 'TLS/Protocols', value: 30, color: '#f43f5e' },
];

import { ActiveScanProgress } from '@/components/ActiveScanProgress';

export default function DashboardPage() {
  const [summary, setSummary] = useState<any>(null);
  const [scans, setScans] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        const [sumData, scanData] = await Promise.all([fetchSummary(), fetchScans()]);
        setSummary(sumData);
        setScans(scanData.scans || []);
      } catch (err) {
        console.error('Failed to load dashboard data:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const stats = [
    {
      name: 'Total Scans',
      value: loading ? '...' : (scans.length || summary?.total_repos_scanned || '0'),
      change: '+12%',
      trend: 'up',
      icon: Box,
      color: 'emerald'
    },
    {
      name: 'Critical Risks',
      value: loading ? '...' : (summary?.critical_risks || '0'),
      change: '-5%',
      trend: 'down',
      icon: ShieldAlert,
      color: 'destructive'
    },
    {
      name: 'Quantum Readiness',
      value: '78%',
      change: '+3%',
      trend: 'up',
      icon: Zap,
      color: 'primary'
    },
    {
      name: 'Compliance Score',
      value: '92/100',
      change: 'Stable',
      trend: 'neutral',
      icon: Lock,
      color: 'secondary'
    },
  ];

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-20">
      <ActiveScanProgress />
      {/* Welcome Header */}
      <section>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center justify-between mb-2"
        >
          <div>
            <h1 className="text-3xl font-extrabold text-white tracking-tight">Security Overview</h1>
            <p className="text-muted-foreground mt-1">Real-time Post-Quantum Cryptography risk monitoring.</p>
          </div>
          <div className="flex gap-3">
            <Link href="/reports" className="px-4 py-2 rounded-lg bg-white/5 border border-white/10 text-sm font-semibold text-white hover:bg-white/10 transition-colors">
              Export Analysis
            </Link>
            <Link href="/assessments" className="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-bold quantum-glow hover:opacity-90 transition-opacity">
              <Plus size={16} />
              Start New Scan
            </Link>
          </div>
        </motion.div>
      </section>

      {/* Stats Grid */}
      <section className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map((stat, index) => (
          <motion.div
            key={stat.name}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
            className="p-6 rounded-2xl glass group hover:border-primary/30 transition-all cursor-default"
          >
            <div className="flex items-start justify-between">
              <div className={cn(
                "w-12 h-12 rounded-xl flex items-center justify-center mb-4 transition-transform group-hover:scale-110",
                stat.color === 'primary' && "bg-primary/10 text-primary",
                stat.color === 'secondary' && "bg-secondary/10 text-secondary",
                stat.color === 'destructive' && "bg-destructive/10 text-destructive",
                stat.color === 'emerald' && "bg-emerald-500/10 text-emerald-500",
              )}>
                <stat.icon size={24} />
              </div>
              {stat.trend !== 'neutral' && (
                <div className={cn(
                  "flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full",
                  stat.trend === 'up' ? "bg-emerald-500/10 text-emerald-500" : "bg-destructive/10 text-destructive"
                )}>
                  {stat.trend === 'up' ? <ArrowUpRight size={12} /> : <TrendingDown size={12} />}
                  {stat.change}
                </div>
              )}
            </div>
            <h3 className="text-sm font-medium text-muted-foreground">{stat.name}</h3>
            <p className="text-3xl font-bold text-white mt-1 tracking-tight">{stat.value}</p>
          </motion.div>
        ))}
      </section>

      {/* Main Charts area */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 p-8 rounded-2xl glass flex flex-col">
          <div className="flex items-center justify-between mb-8">
            <div>
              <h3 className="text-lg font-bold text-white">Risk Distribution</h3>
              <p className="text-xs text-muted-foreground">Across all microservices and infrastructure</p>
            </div>
            <select className="bg-white/5 border border-white/10 rounded-lg text-xs font-semibold px-3 py-1.5 text-white focus:outline-none">
              <option>Last 30 Days</option>
            </select>
          </div>
          <div className="flex-1 min-h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="colorRisks" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff05" vertical={false} />
                <XAxis dataKey="name" stroke="#ffffff20" fontSize={10} tickLine={false} axisLine={false} />
                <YAxis stroke="#ffffff20" fontSize={10} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #ffffff10', borderRadius: '12px' }}
                  itemStyle={{ color: '#22d3ee' }}
                />
                <Area type="monotone" dataKey="risks" stroke="#22d3ee" fillOpacity={1} fill="url(#colorRisks)" strokeWidth={3} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="p-8 rounded-2xl glass">
          <h3 className="text-lg font-bold text-white mb-6">Recent Scans</h3>
          <div className="space-y-4">
            {scans.length > 0 ? scans.map((runId) => (
              <Link
                key={runId}
                href={`/history/${runId}`}
                className="flex items-center justify-between p-3 rounded-xl hover:bg-white/5 border border-transparent hover:border-white/5 transition-all group"
              >
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center text-primary group-hover:animate-pulse">
                    <Activity size={14} />
                  </div>
                  <div>
                    <p className="text-xs font-bold text-white truncate max-w-[120px]">{runId}</p>
                    <p className="text-[10px] text-muted-foreground">Scan successful</p>
                  </div>
                </div>
                <ArrowUpRight size={14} className="text-white/20 group-hover:text-primary transition-colors" />
              </Link>
            )) : (
              <div className="p-10 text-center opacity-30 italic text-xs">No scan history found.</div>
            )}
          </div>
          <Link href="/history" className="block w-full text-center mt-8 py-2.5 rounded-xl border border-white/5 bg-white/5 text-xs font-bold text-white/70 hover:bg-white/10 hover:text-white transition-all">
            View All Activity
          </Link>
        </div>
      </section>
    </div>
  );
}


