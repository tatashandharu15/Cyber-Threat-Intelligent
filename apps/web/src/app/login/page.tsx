"use client";

import { ShieldCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";

export default function LoginPage() {
  const router = useRouter();
  const { login, isAuthenticated, isLoading } = useAuth();
  const [tenant, setTenant] = useState("demo");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mfa, setMfa] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isLoading && isAuthenticated) {
      router.replace("/dashboard");
    }
  }, [isLoading, isAuthenticated, router]);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(tenant.trim(), email.trim(), password, mfa.trim() || undefined);
      toast.success("Signed in");
      router.replace("/dashboard");
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : "Unable to sign in. Please try again.";
      setError(message);
      toast.error(message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-muted/40 p-4">
      <Card className="w-full max-w-sm">
        <CardHeader className="space-y-2 text-center">
          <div className="flex justify-center">
            <ShieldCheck className="h-8 w-8 text-primary" />
          </div>
          <CardTitle className="text-xl">SiberIndo CTI</CardTitle>
          <CardDescription>Sign in to your threat intelligence workspace</CardDescription>
        </CardHeader>
        <CardContent>
          <form className="space-y-4" onSubmit={onSubmit}>
            <div className="space-y-2">
              <Label htmlFor="tenant">Tenant</Label>
              <Input
                id="tenant"
                value={tenant}
                onChange={(e) => setTenant(e.target.value)}
                autoComplete="organization"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="username"
                placeholder="you@company.com"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="mfa">MFA code (if enabled)</Label>
              <Input
                id="mfa"
                inputMode="numeric"
                value={mfa}
                onChange={(e) => setMfa(e.target.value)}
                autoComplete="one-time-code"
                placeholder="123456"
              />
            </div>
            {error ? (
              <p className="text-sm text-destructive" role="alert">
                {error}
              </p>
            ) : null}
            <Button type="submit" className="w-full" disabled={submitting}>
              {submitting ? "Signing in…" : "Sign in"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
