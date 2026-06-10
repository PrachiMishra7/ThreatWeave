import { useState } from "react";
import { Cpu, Send, Sparkles, User } from "lucide-react";

export default function AiAssistant() {
  const [messages, setMessages] = useState<{role: 'system'|'user'|'ai', content: string}[]>([
    { role: 'system', content: 'ThreatWeave AI initialized. System context: Connected to SOC datalake.' },
    { role: 'ai', content: 'Hello analyst. I can help you correlate logs, explain attack campaigns, or suggest remediation steps. What would you like to investigate today?' }
  ]);
  const [input, setInput] = useState("");
  const [isTyping, setIsTyping] = useState(false);

  const handleSend = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;

    const userMsg = input.trim();
    setMessages(prev => [...prev, { role: 'user', content: userMsg }]);
    setInput("");
    setIsTyping(true);

    // Mock AI response delay
    setTimeout(() => {
      setMessages(prev => [...prev, { 
        role: 'ai', 
        content: `I've analyzed the logs matching "${userMsg}". There are strong indications of lateral movement using compromised domain credentials. I recommend isolating the affected subnet and rotating service accounts immediately.` 
      }]);
      setIsTyping(false);
    }, 1500);
  };

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)] bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
      
      {/* Header */}
      <div className="p-4 border-b border-slate-800 bg-slate-950/50 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 bg-slate-900 border border-slate-800 rounded-full flex items-center justify-center">
            <Cpu className="h-5 w-5 text-indigo-400" />
          </div>
          <div>
            <h2 className="font-bold text-white">ThreatWeave Copilot</h2>
            <p className="text-xs text-indigo-400 font-mono flex items-center gap-1">
              <Sparkles className="h-3 w-3" /> Powered by Gemini
            </p>
          </div>
        </div>
      </div>

      {/* Chat History */}
      <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-6">
        {messages.map((msg, idx) => (
          <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            
            {msg.role === 'system' ? (
              <div className="w-full text-center text-[10px] font-mono text-slate-500 my-2">
                --- {msg.content} ---
              </div>
            ) : (
              <div className={`flex gap-3 max-w-[80%] ${msg.role === 'user' ? 'flex-row-reverse' : 'flex-row'}`}>
                <div className={`h-8 w-8 rounded-full flex items-center justify-center shrink-0 border ${
                  msg.role === 'user' ? 'bg-slate-800 border-slate-700' : 'bg-indigo-500/20 border-indigo-500/30'
                }`}>
                  {msg.role === 'user' ? <User className="h-4 w-4 text-slate-400" /> : <Cpu className="h-4 w-4 text-indigo-400" />}
                </div>
                
                <div className={`p-4 rounded-xl ${
                  msg.role === 'user' 
                    ? 'bg-slate-800 text-slate-200 rounded-tr-none' 
                    : 'bg-slate-950 border border-slate-800 text-slate-300 rounded-tl-none'
                }`}>
                  <p className="text-sm leading-relaxed whitespace-pre-wrap">{msg.content}</p>
                </div>
              </div>
            )}
          </div>
        ))}
        {isTyping && (
          <div className="flex justify-start">
             <div className="flex gap-3 max-w-[80%] flex-row">
                <div className="h-8 w-8 rounded-full flex items-center justify-center shrink-0 border bg-indigo-500/20 border-indigo-500/30">
                  <Cpu className="h-4 w-4 text-indigo-400" />
                </div>
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-slate-300 rounded-tl-none flex items-center gap-1">
                  <span className="h-2 w-2 bg-indigo-400 rounded-full animate-bounce"></span>
                  <span className="h-2 w-2 bg-indigo-400 rounded-full animate-bounce delay-100"></span>
                  <span className="h-2 w-2 bg-indigo-400 rounded-full animate-bounce delay-200"></span>
                </div>
             </div>
          </div>
        )}
      </div>

      {/* Input Area */}
      <div className="p-4 bg-slate-950 border-t border-slate-800">
        <form onSubmit={handleSend} className="relative">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask Copilot to analyze an alert, correlate IOCs, or suggest remediations..."
            className="w-full bg-slate-900 border border-slate-700 text-slate-200 rounded-xl pl-4 pr-12 py-4 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/50 transition-all text-sm"
          />
          <button 
            type="submit" 
            disabled={!input.trim() || isTyping}
            className="absolute right-2 top-1/2 -translate-y-1/2 p-2 bg-indigo-500 text-white rounded-lg hover:bg-indigo-400 disabled:opacity-50 disabled:hover:bg-indigo-500 transition-colors"
          >
            <Send className="h-4 w-4" />
          </button>
        </form>
      </div>

    </div>
  );
}
