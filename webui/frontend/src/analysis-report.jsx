import React from 'react'
import { createRoot } from 'react-dom/client'
import AdvancedAnalysis from './components/AdvancedAnalysis'
import './styles.css'

const payload = JSON.parse(document.getElementById('analysis-data').textContent)
createRoot(document.getElementById('analysis-root')).render(
  <AdvancedAnalysis analysis={payload.analysis} artifactIndex={{ other_html: [] }} initialSection={payload.section || 'summary'} />
)
