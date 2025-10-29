import React from 'react';
import { CheckCircleIcon, ShieldCheckIcon, ExclamationTriangleIcon, GlobeAltIcon, HeartIcon } from '@heroicons/react/24/outline';

export default function Dashboard() {
  return (
    <div className="min-h-screen bg-gray-900 p-6">
      <div className="max-w-6xl mx-auto">
        <h1 className="text-3xl font-bold text-white mb-8">CyberSec Suite Dashboard</h1>
        
        {/* Status Card */}
        <div className="bg-gray-800 rounded-xl p-8 mb-8 border border-gray-700">
          <div className="flex items-center justify-center flex-col text-center">
            <CheckCircleIcon className="h-16 w-16 text-green-500 mb-4" />
            <h2 className="text-2xl font-bold text-white mb-2">Your system is protected</h2>
            <p className="text-white-400">All security features are active and monitoring your system</p>
          </div>
        </div>

        {/* Feature Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Scans Card */}
          <div className="bg-gray-800 rounded-xl p-6 border border-gray-700 hover:border-purple-500 transition-colors duration-200">
            <div className="flex items-start justify-between mb-4">
              <ShieldCheckIcon className="h-12 w-12 text-purple-500" />
              <span className="bg-purple-500 text-white text-xs px-2 py-1 rounded-full">Active</span>
            </div>
            <h3 className="text-xl font-semibold text-white mb-2">Scans</h3>
            <p className="text-white-400 mb-4">Real-time system scanning and monitoring</p>
            <div className="bg-gray-700 rounded-lg p-3">
              <p className="text-sm text-white-300">Last scan completed</p>
              <p className="text-white font-medium">2 hours ago</p>
            </div>
          </div>

          {/* Threats Blocked Card */}
          <div className="bg-gray-800 rounded-xl p-6 border border-gray-700 hover:border-purple-500 transition-colors duration-200">
            <div className="flex items-start justify-between mb-4">
              <ExclamationTriangleIcon className="h-12 w-12 text-purple-500" />
              <span className="bg-green-500 text-white text-xs px-2 py-1 rounded-full">Protected</span>
            </div>
            <h3 className="text-xl font-semibold text-white mb-2">Threats Blocked</h3>
            <p className="text-white-400 mb-4">Malware and threats prevented</p>
            <div className="bg-gray-700 rounded-lg p-3">
              <p className="text-sm text-white-300">Threats blocked today</p>
              <p className="text-white font-medium text-2xl">47</p>
            </div>
          </div>

          {/* Dark Web Monitoring Card */}
          <div className="bg-gray-800 rounded-xl p-6 border border-gray-700 hover:border-purple-500 transition-colors duration-200">
            <div className="flex items-start justify-between mb-4">
              <GlobeAltIcon className="h-12 w-12 text-purple-500" />
              <span className="bg-blue-500 text-white text-xs px-2 py-1 rounded-full">Monitoring</span>
            </div>
            <h3 className="text-xl font-semibold text-white mb-2">Dark Web Monitoring</h3>
            <p className="text-white-400 mb-4">Identity and data breach monitoring</p>
            <div className="bg-gray-700 rounded-lg p-3">
              <p className="text-sm text-white-300">Status</p>
              <p className="text-green-400 font-medium">No breaches detected</p>
            </div>
          </div>

          {/* System Health Card */}
          <div className="bg-gray-800 rounded-xl p-6 border border-gray-700 hover:border-purple-500 transition-colors duration-200">
            <div className="flex items-start justify-between mb-4">
              <HeartIcon className="h-12 w-12 text-purple-500" />
              <span className="bg-green-500 text-white text-xs px-2 py-1 rounded-full">Excellent</span>
            </div>
            <h3 className="text-xl font-semibold text-white mb-2">System Health</h3>
            <p className="text-white-400 mb-4">Overall system performance and security</p>
            <div className="bg-gray-700 rounded-lg p-3">
              <div className="flex justify-between items-center mb-2">
                <p className="text-sm text-white-300">Health Score</p>
                <p className="text-green-400 font-medium">98%</p>
              </div>
              <div className="w-full bg-gray-600 rounded-full h-2">
                <div className="bg-green-500 h-2 rounded-full" style={{ width: '98%' }}></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}