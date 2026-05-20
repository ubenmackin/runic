import { render, screen } from '@testing-library/react'
import { describe, test, expect } from 'vitest'
import { Server, Package, Shield, Check } from 'lucide-react'
import StepIndicator from './StepIndicator'

describe('StepIndicator', () => {
  const steps = [
    { key: 'peer', label: 'Peer', icon: Server },
    { key: 'service', label: 'Service', icon: Package },
    { key: 'policy', label: 'Policy', icon: Shield },
    { key: 'review', label: 'Review', icon: Check },
  ]

  describe('rendering', () => {
    test('renders all step labels', () => {
      render(<StepIndicator steps={steps} currentStep="peer" />)

      expect(screen.getByText('Peer')).toBeInTheDocument()
      expect(screen.getByText('Service')).toBeInTheDocument()
      expect(screen.getByText('Policy')).toBeInTheDocument()
      expect(screen.getByText('Review')).toBeInTheDocument()
    })

    test('renders all step icons', () => {
      const { container } = render(
        <StepIndicator steps={steps} currentStep="peer" />
      )

      const svgs = container.querySelectorAll('svg')
      expect(svgs.length).toBe(steps.length)
    })

    test('renders connector lines between steps', () => {
      const { container } = render(
        <StepIndicator steps={steps} currentStep="peer" />
      )

      // There should be (steps.length - 1) connector divs
      const connectors = container.querySelectorAll('.h-0\\.5')
      expect(connectors.length).toBe(steps.length - 1)
    })
  })

  describe('active step', () => {
    test('highlights the current step with active styling', () => {
      const { container } = render(
        <StepIndicator steps={steps} currentStep="service" />
      )

      // Active step should have purple-active background
      const stepDivs = container.querySelectorAll('.w-8.h-8')
      const activeStep = stepDivs[1] // service is index 1
      expect(activeStep.className).toContain('bg-purple-active')
    })

    test('active step label has purple-active text', () => {
      const { container } = render(
        <StepIndicator steps={steps} currentStep="service" />
      )

      const labels = container.querySelectorAll('.text-xs.font-medium')
      const activeLabel = labels[1] // service is index 1
      expect(activeLabel.className).toContain('text-purple-active')
    })

    test('inactive step labels have gray text', () => {
      const { container } = render(
        <StepIndicator steps={steps} currentStep="peer" />
      )

      const labels = container.querySelectorAll('.text-xs.font-medium')
      const inactiveLabel = labels[1] // service is index 1, not active
      expect(inactiveLabel.className).toContain('text-gray-500')
    })
  })

  describe('completed steps', () => {
    test('completed steps have green background', () => {
      const { container } = render(
        <StepIndicator steps={steps} currentStep="policy" />
      )

      const stepDivs = container.querySelectorAll('.w-8.h-8')
      // peer (index 0) and service (index 1) are completed
      expect(stepDivs[0].className).toContain('bg-green-500')
      expect(stepDivs[1].className).toContain('bg-green-500')
    })

    test('completed steps show check icon', () => {
      const { container } = render(
        <StepIndicator steps={steps} currentStep="policy" />
      )

      // The Check icon is rendered as an SVG within completed step circles
      const stepDivs = container.querySelectorAll('.w-8.h-8')
      const completedStepSvg = stepDivs[0].querySelector('svg')
      expect(completedStepSvg).toBeInTheDocument()
    })

    test('connector lines before current step are green', () => {
      const { container } = render(
        <StepIndicator steps={steps} currentStep="policy" />
      )

      const connectors = container.querySelectorAll('.h-0\\.5')
      // Connectors before the current index should be green
      expect(connectors[0].className).toContain('bg-green-500')
      expect(connectors[1].className).toContain('bg-green-500')
    })

    test('connector lines after current step are gray', () => {
      const { container } = render(
        <StepIndicator steps={steps} currentStep="peer" />
      )

      const connectors = container.querySelectorAll('.h-0\\.5')
      // All connectors should be gray since no steps are completed
      connectors.forEach((conn) => {
        expect(conn.className).toContain('bg-gray-200')
      })
    })
  })

  describe('first step', () => {
    test('renders correctly when on first step', () => {
      const { container } = render(
        <StepIndicator steps={steps} currentStep="peer" />
      )

      const stepDivs = container.querySelectorAll('.w-8.h-8')
      expect(stepDivs[0].className).toContain('bg-purple-active')
      // No completed steps
      expect(stepDivs[0].className).not.toContain('bg-green-500')
    })
  })

  describe('last step', () => {
    test('renders correctly when on last step', () => {
      const { container } = render(
        <StepIndicator steps={steps} currentStep="review" />
      )

      const stepDivs = container.querySelectorAll('.w-8.h-8')
      // All previous steps should be completed
      expect(stepDivs[0].className).toContain('bg-green-500')
      expect(stepDivs[1].className).toContain('bg-green-500')
      expect(stepDivs[2].className).toContain('bg-green-500')
      expect(stepDivs[3].className).toContain('bg-purple-active')
    })
  })

  describe('two steps', () => {
    test('renders with only two steps', () => {
      const twoSteps = [
        { key: 'step1', label: 'Step 1', icon: Server },
        { key: 'step2', label: 'Step 2', icon: Check },
      ]

      const { container } = render(
        <StepIndicator steps={twoSteps} currentStep="step1" />
      )

      expect(screen.getByText('Step 1')).toBeInTheDocument()
      expect(screen.getByText('Step 2')).toBeInTheDocument()
      // Only one connector
      const connectors = container.querySelectorAll('.h-0\\.5')
      expect(connectors.length).toBe(1)
    })
  })

  describe('single step', () => {
    test('renders with a single step', () => {
      const singleStep = [
        { key: 'only', label: 'Only Step', icon: Server },
      ]

      const { container } = render(
        <StepIndicator steps={singleStep} currentStep="only" />
      )

      expect(screen.getByText('Only Step')).toBeInTheDocument()
      // No connectors for single step
      const connectors = container.querySelectorAll('.h-0\\.5')
      expect(connectors.length).toBe(0)
    })
  })

  describe('unknown currentStep', () => {
    test('renders without crashing when currentStep does not match any step', () => {
      const { container } = render(
        <StepIndicator steps={steps} currentStep="unknown" />
      )

      // All steps should be in default (inactive) state
      const stepDivs = container.querySelectorAll('.w-8.h-8')
      stepDivs.forEach((div) => {
        expect(div.className).toContain('bg-gray-200')
      })
    })
  })
})
