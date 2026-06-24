import React from "react";
import { motion } from "motion/react";

export default function PageWrapper({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -15 }}
      transition={{ duration: 0.3, ease: "easeInOut" }}
      className={`w-full h-full ${className}`}
    >
      {children}
    </motion.div>
  );
}
