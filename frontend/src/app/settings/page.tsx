'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
    Settings as SettingsIcon,
    Cpu,
    Shield,
    Database,
    Zap,
    Save,
    RefreshCw,
    CheckCircle2,
    AlertTriangle
} from 'lucide-react';
import { fetchSettings, updateSettings } from '@/lib/api';
import { cn } from '@/lib/utils';

export default function SettingsPage() {
    const [settings, setSettings] = useState<any>({ gemini_model: '' });
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [success, setSuccess] = useState(false);
    const [status, setStatus] = useState<any>(null);

    useEffect(() => {
        async function loadData() {
            try {
                const [settData, healthData] = await Promise.all([
                    fetchSettings(),
                    fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/health`).then(r => r.json())
                ]);
                setSettings(settData);
                setStatus(healthData);
            } catch (err) {
                console.error('Failed to load settings:', err);
            } finally {
                setLoading(false);
            }
        }
        loadData();
    }, []);

    const handleSave = async (e: React.FormEvent) => {
        e.preventDefault();
        setSaving(true);
        setSuccess(false);
        try {
            await updateSettings({ gemini_model: settings.gemini_model });
            setSuccess(true);
            setTimeout(() => setSuccess(false), 3000);
        } catch (err) {
            console.error('Update failed:', err);
            alert('Failed to update settings.');
        } finally {
            setSaving(false);
        }
    };

    return (
        <div className="space-y-8 max-w-4xl mx-auto pb-20">
            <header>
                <h1 className="text-3xl font-extrabold text-white tracking-tight">System Settings</h1>
                <p className="text-muted-foreground mt-1">Configure scanning engines, AI models, and monitor backend infrastructure.</p>
            </header>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                <div className="md:col-span-2 space-y-6">
                    <section className="glass rounded-3xl p-8 border border-white/5">
                        <h3 className="text-lg font-bold text-white mb-6 flex items-center gap-2">
                            <Cpu className="text-primary" size={20} />
                            AI Reasoning Engine
                        </h3>

                        <form onSubmit={handleSave} className="space-y-6">
                            <div className="space-y-2">
                                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Analysis Model</label>
                                <select
                                    value={settings.gemini_model}
                                    onChange={(e) => setSettings({ ...settings, gemini_model: e.target.value })}
                                    className="w-full bg-white/5 border border-white/10 rounded-2xl p-4 text-white focus:outline-none focus:ring-2 focus:ring-primary/50 appearance-none cursor-pointer hover:bg-white/10 transition-all font-mono"
                                >
                                    <option value="gemini-3-flash-preview">Gemini 3 Flash (Fastest)</option>
                                    <option value="gemini-1.5-pro">Gemini 1.5 Pro (Deepest Analysis)</option>
                                    <option value="gemini-1.5-flash">Gemini 1.5 Flash (Balanced)</option>
                                </select>
                            </div>

                            <div className="p-4 rounded-2xl bg-primary/5 border border-primary/10 text-xs text-primary/80 leading-relaxed">
                                <strong>Note:</strong> Model changes are applied per-session in the backend. To change the persistent default, update the <code>GEMINI_MODEL</code> environment variable in your <code>docker-compose.yml</code>.
                            </div>

                            <button
                                type="submit"
                                disabled={saving || loading}
                                className={cn(
                                    "w-full py-4 rounded-2xl font-black text-lg transition-all flex items-center justify-center gap-3",
                                    success
                                        ? "bg-emerald-500 text-white shadow-[0_0_20px_rgba(16,185,129,0.4)]"
                                        : "bg-primary text-primary-foreground quantum-glow hover:opacity-90"
                                )}
                            >
                                {saving ? (
                                    <RefreshCw className="animate-spin" size={24} />
                                ) : success ? (
                                    <><CheckCircle2 size={24} /> Configuration Saved</>
                                ) : (
                                    <><Save size={24} /> Apply Changes</>
                                )}
                            </button>
                        </form>
                    </section>

                    <section className="glass rounded-3xl p-8 border border-white/5">
                        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                            <Shield className="text-primary" size={20} />
                            Scan Policies
                        </h3>
                        <div className="space-y-4">
                            <div className="flex items-center justify-between p-4 rounded-2xl bg-white/5 border border-white/10">
                                <div>
                                    <div className="text-sm font-bold text-white">Local Scan Access</div>
                                    <div className="text-[10px] text-muted-foreground">Allow scanning of host filesystem paths</div>
                                </div>
                                <div className={cn(
                                    "px-2 py-1 rounded-md text-[10px] font-bold uppercase",
                                    settings.allow_local_scan ? "bg-emerald-500/10 text-emerald-500" : "bg-destructive/10 text-destructive"
                                )}>
                                    {settings.allow_local_scan ? 'Enabled' : 'Disabled'}
                                </div>
                            </div>
                        </div>
                    </section>
                </div>

                <aside className="space-y-6">
                    <div className="glass rounded-3xl p-6 border border-white/5">
                        <h4 className="font-bold text-white mb-4 flex items-center gap-2">
                            <Database className="text-primary" size={18} />
                            Infrastucture Status
                        </h4>

                        <div className="space-y-4">
                            <div className="flex items-center justify-between">
                                <span className="text-xs text-muted-foreground">MQ (Redis)</span>
                                <span className={cn(
                                    "flex items-center gap-1.5 text-xs font-bold",
                                    status?.redis === 'connected' ? "text-emerald-500" : "text-destructive"
                                )}>
                                    <div className={cn("w-1.5 h-1.5 rounded-full", status?.redis === 'connected' ? "bg-emerald-500 animate-pulse" : "bg-destructive")} />
                                    {status?.redis || 'Disconnected'}
                                </span>
                            </div>
                            <div className="flex items-center justify-between border-t border-white/5 pt-4">
                                <span className="text-xs text-muted-foreground">Storage (SQLite)</span>
                                <span className={cn(
                                    "flex items-center gap-1.5 text-xs font-bold",
                                    status?.database === 'accessible' ? "text-emerald-500" : "text-destructive"
                                )}>
                                    <div className={cn("w-1.5 h-1.5 rounded-full", status?.database === 'accessible' ? "bg-emerald-500" : "bg-destructive")} />
                                    {status?.database === 'accessible' ? 'Healthy' : 'Error'}
                                </span>
                            </div>
                            <div className="flex items-center justify-between border-t border-white/5 pt-4">
                                <span className="text-xs text-muted-foreground">Active Workers</span>
                                <span className="text-xs font-mono text-white bg-white/10 px-2 py-0.5 rounded">2/2</span>
                            </div>
                        </div>
                    </div>

                    <div className="p-6 rounded-3xl bg-secondary/10 border border-secondary/20">
                        <div className="flex items-center gap-2 text-secondary mb-3">
                            <AlertTriangle size={18} />
                            <h4 className="font-bold text-xs uppercase tracking-wider">Security Advisory</h4>
                        </div>
                        <p className="text-[11px] text-white/70 leading-relaxed">
                            Updating your Gemini model will immediately impact the depth of the "Deep Core Scan" strategy. Use <strong>Gemini 1.5 Pro</strong> for critical production audits to minimize true negatives.
                        </p>
                    </div>

                    <div className="text-center">
                        <p className="text-[10px] text-muted-foreground">LatticeGuard Platform Version 1.0.4-stable</p>
                    </div>
                </aside>
            </div>
        </div>
    );
}
