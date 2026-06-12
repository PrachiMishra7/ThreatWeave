import React, { useState, useEffect, useRef } from "react";
import { Cpu, Send, Sparkles, User, ShieldAlert } from "lucide-react";
import { motion, AnimatePresence } from "motion/react";

export default function AiAssistant() {
  const [messages, setMessages] = useState<{role: 'system'|'user'|'ai', content: string}[]>([
    { role: 'system', content: 'ThreatWeave AI initialized. System context: Connected to SOC datalake.' },
    { role: 'ai', content: 'Hello analyst. I can help you correlate logs, explain attack campaigns, or suggest remediation steps. What would you like to investigate today?' }
  ]);
  const [input, setInput] = useState("");
  const [isTyping, setIsTyping] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;

    const userMsg = input.trim();
    const newMessages = [...messages, { role: 'user' as const, content: userMsg }];
    setMessages(newMessages);
    setInput("");
    setIsTyping(true);

    try {
      const apiMessages = newMessages.map(m => ({
        role: m.role === 'ai' ? 'assistant' : m.role,
        content: m.content
      }));

      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages: apiMessages })
      });

      const data = await response.json();
      if (response.ok && data.reply) {
        setMessages(prev => [...prev, { role: 'ai', content: data.reply }]);
      } else {
        setMessages(prev => [...prev, { role: 'ai', content: `Error: ${data.error || 'Failed to get response'}` }]);
      }
    } catch (err) {
      setMessages(prev => [...prev, { role: 'ai', content: 'Network error occurred while fetching AI response.' }]);
    } finally {
      setIsTyping(false);
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)] bg-gradient-to-b from-slate-900 to-slate-950 border border-slate-800/60 rounded-2xl overflow-hidden shadow-2xl relative backdrop-blur-xl">
      {/* Glow Effect behind */}
      <div className="absolute -top-40 -right-40 w-96 h-96 bg-indigo-500/10 blur-[120px] rounded-full pointer-events-none" />
      <div className="absolute -bottom-40 -left-40 w-96 h-96 bg-teal-500/10 blur-[120px] rounded-full pointer-events-none" />

      {/* Header */}
      <div className="p-5 border-b border-slate-800/60 bg-slate-950/40 backdrop-blur-md flex items-center justify-between z-10">
        <div className="flex items-center gap-4">
          <div className="relative">
            <div className="absolute inset-0 bg-indigo-500/20 rounded-full blur-md animate-pulse"></div>
            <div className="h-12 w-12 bg-slate-900 border border-indigo-500/30 rounded-full flex items-center justify-center relative shadow-[0_0_15px_rgba(99,102,241,0.2)]">
              <Cpu className="h-6 w-6 text-indigo-400" />
            </div>
          </div>
          <div>
            <h2 className="text-lg font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 via-purple-400 to-teal-400 tracking-wide flex items-center gap-2">
              ThreatWeave Copilot <Sparkles className="h-4 w-4 text-purple-400" />
            </h2>
            <p className="text-xs text-slate-400 font-medium flex items-center gap-1 mt-0.5">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-teal-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-teal-500"></span>
              </span>
              Connected to SOC
            </p>
          </div>
        </div>
      </div>

      {/* Chat History */}
      <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-6 z-10 scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-transparent">
        <AnimatePresence initial={false}>
          {messages.map((msg, idx) => (
            <motion.div 
              key={idx} 
              initial={{ opacity: 0, y: 15, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              transition={{ duration: 0.3, ease: "easeOut" }}
              className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              {msg.role === 'system' ? (
                <div className="w-full flex items-center justify-center my-4 opacity-70">
                  <div className="bg-slate-800/50 backdrop-blur-sm border border-slate-700/50 rounded-full px-4 py-1.5 flex items-center gap-2">
                    <ShieldAlert className="h-3.5 w-3.5 text-slate-400" />
                    <span className="text-xs font-mono text-slate-300 tracking-wider">
                      {msg.content.replace('ThreatWeave AI initialized. System context: ', '')}
                    </span>
                  </div>
                </div>
              ) : (
                <div className={`flex gap-3 max-w-[85%] ${msg.role === 'user' ? 'flex-row-reverse' : 'flex-row'}`}>
                  <div className={`h-9 w-9 rounded-full flex items-center justify-center shrink-0 border shadow-lg ${
                    msg.role === 'user' 
                      ? 'bg-gradient-to-br from-slate-700 to-slate-800 border-slate-600' 
                      : 'bg-gradient-to-br from-indigo-500/20 to-purple-500/20 border-indigo-500/40 shadow-[0_0_10px_rgba(99,102,241,0.15)]'
                  }`}>
                    {msg.role === 'user' ? <User className="h-4 w-4 text-slate-300" /> : <Cpu className="h-4.5 w-4.5 text-indigo-300" />}
                  </div>
                  
                  <div className={`p-4 rounded-2xl shadow-md ${
                    msg.role === 'user' 
                      ? 'bg-slate-800/90 border border-slate-700/80 text-slate-200 rounded-tr-sm' 
                      : 'bg-slate-900/80 border border-indigo-500/20 text-slate-300 rounded-tl-sm backdrop-blur-sm shadow-[0_4px_20px_-4px_rgba(0,0,0,0.3)]'
                  }`}>
                    <p className="text-[14.5px] leading-relaxed whitespace-pre-wrap font-medium">{msg.content}</p>
                  </div>
                </div>
              )}
            </motion.div>
          ))}
          {isTyping && (
            <motion.div 
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.9 }}
              className="flex justify-start"
            >
               <div className="flex gap-3 max-w-[80%] flex-row">
                  <div className="h-9 w-9 rounded-full flex items-center justify-center shrink-0 border bg-gradient-to-br from-indigo-500/20 to-purple-500/20 border-indigo-500/40 shadow-[0_0_10px_rgba(99,102,241,0.15)]">
                    <Cpu className="h-4.5 w-4.5 text-indigo-300" />
                  </div>
                  <div className="p-4 rounded-2xl bg-slate-900/80 border border-indigo-500/20 text-slate-300 rounded-tl-sm backdrop-blur-sm flex items-center gap-1.5 shadow-md h-12">
                    <motion.span animate={{ y: [0, -5, 0] }} transition={{ repeat: Infinity, duration: 0.6, delay: 0 }} className="h-2 w-2 bg-indigo-400 rounded-full"></motion.span>
                    <motion.span animate={{ y: [0, -5, 0] }} transition={{ repeat: Infinity, duration: 0.6, delay: 0.15 }} className="h-2 w-2 bg-indigo-400 rounded-full"></motion.span>
                    <motion.span animate={{ y: [0, -5, 0] }} transition={{ repeat: Infinity, duration: 0.6, delay: 0.3 }} className="h-2 w-2 bg-indigo-400 rounded-full"></motion.span>
                  </div>
               </div>
            </motion.div>
          )}
        </AnimatePresence>
        <div ref={bottomRef} />
      </div>

      {/* Input Area */}
      <div className="p-4 bg-slate-950/80 border-t border-slate-800/60 backdrop-blur-md z-10">
        <form onSubmit={handleSend} className="relative group">
          <div className="absolute -inset-0.5 bg-gradient-to-r from-indigo-500 to-teal-500 rounded-xl blur opacity-20 group-focus-within:opacity-40 transition duration-500"></div>
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask Copilot to analyze alerts, correlate IOCs..."
            className="relative w-full bg-slate-900/90 border border-slate-700/80 text-slate-200 rounded-xl pl-5 pr-14 py-4 focus:outline-none focus:border-indigo-500/70 focus:ring-1 focus:ring-indigo-500/70 transition-all text-[15px] shadow-inner placeholder:text-slate-500 font-medium"
          />
          <button 
            type="submit" 
            disabled={!input.trim() || isTyping}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 p-2.5 bg-indigo-500 text-white rounded-lg hover:bg-indigo-400 disabled:opacity-50 disabled:hover:bg-indigo-500 transition-all shadow-[0_0_15px_rgba(99,102,241,0.4)] disabled:shadow-none transform active:scale-95"
          >
            <Send className="h-4.5 w-4.5" />
          </button>
        </form>
      </div>

    </div>
  );
}
