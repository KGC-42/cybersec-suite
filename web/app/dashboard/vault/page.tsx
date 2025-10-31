'use client'

import { useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { ExternalLink, Key, Shield, Lock } from 'lucide-react'

export default function VaultPage() {
  const vaultUrl = 'https://server-production-f96b.up.railway.app'

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">Password Vault</h1>
        <p className="text-slate-400">Securely manage your passwords with GuardianOS Vault</p>
      </div>

      <Card className="bg-slate-800 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Key className="w-5 h-5 text-purple-500" />
            GuardianOS Vault
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-slate-300">
            Your password vault is powered by Vaultwarden, a secure and open-source password manager 
            compatible with Bitwarden.
          </p>
          
          <div className="flex flex-col gap-4">
            <Button
              onClick={() => window.open(vaultUrl, '_blank')}
              className="bg-purple-600 hover:bg-purple-700 text-white"
            >
              <ExternalLink className="w-4 h-4 mr-2" />
              Open Password Vault
            </Button>

            <div className="grid gap-4 md:grid-cols-2">
              <Card className="bg-slate-900 border-slate-700">
                <CardContent className="pt-6">
                  <Shield className="w-8 h-8 text-green-500 mb-3" />
                  <h3 className="text-white font-semibold mb-2">Secure Storage</h3>
                  <p className="text-slate-400 text-sm">
                    Your passwords are encrypted with AES-256 encryption
                  </p>
                </CardContent>
              </Card>

              <Card className="bg-slate-900 border-slate-700">
                <CardContent className="pt-6">
                  <Lock className="w-8 h-8 text-blue-500 mb-3" />
                  <h3 className="text-white font-semibold mb-2">Browser Extension</h3>
                  <p className="text-slate-400 text-sm">
                    Download the Bitwarden extension and point it to your vault
                  </p>
                </CardContent>
              </Card>
            </div>
          </div>

          <div className="bg-slate-900 rounded-lg p-4 border border-slate-700">
            <h4 className="text-white font-medium mb-2">Server URL for Browser Extension:</h4>
            <code className="text-purple-400 bg-slate-950 px-3 py-2 rounded block">
              {vaultUrl}
            </code>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}