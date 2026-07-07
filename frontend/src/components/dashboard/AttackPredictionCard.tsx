'use client';

import { cn } from '@/lib/utils';
import { ArrowRight, Target, AlertTriangle, Siren } from 'lucide-react';

interface AttackStep {
  stage: string;
  probability: number;
  timeEstimate: string;
  targetAsset: string;
  mitreId: string;
}

const currentStage = 'Credential Dumping (T1003.001)';
const prediction: AttackStep = {
  stage: 'Lateral Movement via WMI (T1047)',
  probability: 87,
  timeEstimate: '~12 minutes',
  targetAsset: 'SQL-01 (10.0.1.20)',
  mitreId: 'T1047',
};

const recommendations = [
  'Enable Credential Guard on all domain controllers',
  'Restrict WMI access to authorized admin workstations',
  'Deploy additional logging on SQL-01',
  'Initiate automated credential rotation for service accounts',
];

export function AttackPredictionCard() {
  return (
    <div className="bg-surface-card border border-accent-red/30 rounded-xl overflow-hidden shadow-glow-red/20">
      <div className="px-5 py-4 border-b border-surface-border flex items-center gap-3">
        <div className="p-2 rounded-lg bg-accent-red/20 text-accent-red">
          <Siren className="h-4 w-4" />
        </div>
        <div>
          <h3 className="text-sm font-semibold text-white">AI Attack Prediction</h3>
          <p className="text-[10px] text-gray-500 font-mono">Machine Learning · Real-time</p>
        </div>
        <div className="ml-auto flex items-center gap-1">
          <span className="w-1.5 h-1.5 rounded-full bg-accent-red animate-pulse" />
          <span className="text-[10px] text-accent-red font-mono">ACTIVE</span>
        </div>
      </div>

      <div className="p-5 space-y-5">
        {/* Current / Predicted stages */}
        <div className="flex items-center gap-3">
          <div className="flex-1">
            <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Current Stage</p>
            <div className="px-3 py-2 rounded-lg bg-accent-red/10 border border-accent-red/30">
              <p className="text-xs text-accent-red font-medium">{currentStage}</p>
            </div>
          </div>
          <div className="shrink-0 mt-5">
            <div className="p-1.5 rounded-full bg-accent-red/20">
              <ArrowRight className="h-4 w-4 text-accent-red" />
            </div>
          </div>
          <div className="flex-1">
            <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Predicted Next</p>
            <div className="px-3 py-2 rounded-lg bg-accent-orange/10 border border-accent-orange/30">
              <p className="text-xs text-accent-orange font-medium">{prediction.stage}</p>
            </div>
          </div>
        </div>

        {/* Probability */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-gray-400">Probability of progression</span>
            <span className="text-sm font-bold text-accent-red font-mono">{prediction.probability}%</span>
          </div>
          <div className="h-2 bg-surface rounded-full overflow-hidden">
            <div
              className="h-full rounded-full bg-gradient-to-r from-accent-orange to-accent-red transition-all duration-1000"
              style={{ width: `${prediction.probability}%` }}
            />
          </div>
        </div>

        {/* Time estimate */}
        <div className="flex items-center gap-3 px-3 py-2 rounded-lg bg-surface/50">
          <div className="p-1.5 rounded bg-accent-cyan/10 text-accent-cyan">
            <AlertTriangle className="h-3.5 w-3.5" />
          </div>
          <div>
            <p className="text-[10px] text-gray-500">Estimated time to next step</p>
            <p className="text-xs text-accent-cyan font-mono font-medium">{prediction.timeEstimate}</p>
          </div>
        </div>

        {/* Target asset */}
        <div className="flex items-center gap-3 px-3 py-2 rounded-lg bg-surface/50">
          <div className="p-1.5 rounded bg-accent-red/10 text-accent-red">
            <Target className="h-3.5 w-3.5" />
          </div>
          <div>
            <p className="text-[10px] text-gray-500">Likely target asset</p>
            <p className="text-xs text-white font-mono font-medium">{prediction.targetAsset}</p>
            <p className="text-[10px] text-gray-500 font-mono">MITRE: {prediction.mitreId}</p>
          </div>
        </div>

        {/* Recommendations */}
        <div>
          <p className="text-xs text-gray-400 font-medium mb-2">Recommended Actions</p>
          <div className="space-y-1.5">
            {recommendations.map((rec, idx) => (
              <div key={idx} className="flex items-start gap-2">
                <div className="w-4 h-4 rounded-full bg-accent-cyan/20 text-accent-cyan flex items-center justify-center shrink-0 mt-0.5">
                  <span className="text-[10px] font-bold">{idx + 1}</span>
                </div>
                <p className="text-xs text-gray-300">{rec}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
