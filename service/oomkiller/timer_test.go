package oomkiller

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// VPN4TV: in the Network Extension a trigger cools down and the timer polls at
// the armed interval; with a memory limit (Android, desktop) triggered still
// holds down to resume and polls at min_interval.
func TestNetworkExtensionTriggerCoolsDown(t *testing.T) {
	t.Parallel()
	config, err := buildTimerConfig(option.OOMKillerServiceOptions{}, DefaultAppleNetworkExtensionMemoryLimit, policyModeNetworkExtension, false)
	require.NoError(t, err)
	timer := newAdaptiveTimer(nil, nil, config, nil)
	trigger := memorySample{usage: timer.limitThresholds.trigger}
	aboveResume := memorySample{usage: timer.limitThresholds.resume + 1}

	timer.state = pressureStateTriggered
	timer.triggeredAt = time.Now()
	require.Equal(t, pressureStateTriggered, timer.nextState(aboveResume))
	require.Equal(t, config.armedInterval, timer.intervalForState())

	timer.triggeredAt = time.Now().Add(-networkExtensionTriggerCooldown)
	require.Equal(t, pressureStateNormal, timer.nextState(aboveResume))
	require.Equal(t, pressureStateArmed, timer.nextState(trigger))

	timer.state = pressureStateArmed
	require.Equal(t, pressureStateTriggered, timer.nextState(trigger))
}

func TestNetworkExtensionFastPollOnlyAfterPressure(t *testing.T) {
	t.Parallel()
	config, err := buildTimerConfig(option.OOMKillerServiceOptions{}, DefaultAppleNetworkExtensionMemoryLimit, policyModeNetworkExtension, false)
	require.NoError(t, err)
	timer := newAdaptiveTimer(nil, nil, config, nil)
	timer.state = pressureStateArmed
	timer.forceMinInterval = true
	timer.pressureBaselineTime = time.Now()
	require.Equal(t, config.minInterval, timer.intervalForState())
	timer.pressureBaselineTime = time.Now().Add(-config.maxInterval)
	require.Equal(t, config.armedInterval, timer.intervalForState())
	// Back to normal: backs off from the armed interval up to max_interval.
	timer.state = pressureStateNormal
	timer.forceMinInterval = false
	require.Equal(t, min(2*config.armedInterval, config.maxInterval), timer.intervalForState())
}

func TestMemoryLimitTriggerUnchanged(t *testing.T) {
	t.Parallel()
	config, err := buildTimerConfig(option.OOMKillerServiceOptions{}, 100*1024*1024, policyModeMemoryLimit, false)
	require.NoError(t, err)
	timer := newAdaptiveTimer(nil, nil, config, nil)
	timer.state = pressureStateTriggered
	timer.triggeredAt = time.Now().Add(-time.Hour)
	require.Equal(t, pressureStateTriggered, timer.nextState(memorySample{usage: timer.limitThresholds.resume + 1}))
	require.Equal(t, config.minInterval, timer.intervalForState())
	require.Equal(t, pressureStateNormal, timer.nextState(memorySample{usage: timer.limitThresholds.resume - 1}))
}
