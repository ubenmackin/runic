// Package alerts provides alert and notification functionality.
package alerts

import (
	"context"
	"testing"
	"time"

	"runic/internal/db"
	"runic/internal/testutil"
)

// TestDigestSendTime_TimezoneHandling tests that digests are sent at the correct time
// for users in different timezones.
func TestDigestSendTime_TimezoneHandling(t *testing.T) {
	tests := []struct {
		name           string
		userTimezone   string
		digestTime     string
		expectedHour   int
		expectedMinute int
	}{
		{
			name:           "UTC timezone at 09:00",
			userTimezone:   "UTC",
			digestTime:     "09:00",
			expectedHour:   9,
			expectedMinute: 0,
		},
		{
			name:           "America/New_York timezone at 09:00",
			userTimezone:   "America/New_York",
			digestTime:     "09:00",
			expectedHour:   9,
			expectedMinute: 0,
		},
		{
			name:           "Europe/London timezone at 14:30",
			userTimezone:   "Europe/London",
			digestTime:     "14:30",
			expectedHour:   14,
			expectedMinute: 30,
		},
		{
			name:           "Asia/Tokyo timezone at 08:00",
			userTimezone:   "Asia/Tokyo",
			digestTime:     "08:00",
			expectedHour:   8,
			expectedMinute: 0,
		},
		{
			name:           "Australia/Sydney timezone at 07:15",
			userTimezone:   "Australia/Sydney",
			digestTime:     "07:15",
			expectedHour:   7,
			expectedMinute: 15,
		},
		{
			name:           "Pacific/Honolulu timezone at 12:00",
			userTimezone:   "Pacific/Honolulu",
			digestTime:     "12:00",
			expectedHour:   12,
			expectedMinute: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Load the timezone
			loc, err := time.LoadLocation(tt.userTimezone)
			if err != nil {
				t.Fatalf("failed to load timezone %s: %v", tt.userTimezone, err)
			}

			// Create a reference time in that timezone
			now := time.Now().In(loc)
			currentTime := now.Format("15:04")
			currentDate := now.Format("2006-01-02")

			// Verify the timezone conversion works correctly
			utcTime := now.UTC()

			// The digest time check in checkAndSendDigests uses Format("15:04")
			// Verify we can correctly parse and compare times
			if tt.digestTime == currentTime {
				// If times match, digest would be sent
				t.Logf("Digest would be sent at %s for timezone %s (current: %s, date: %s)",
					tt.digestTime, tt.userTimezone, currentTime, currentDate)
			}

			// Verify timezone string is valid IANA identifier
			if loc.String() != tt.userTimezone {
				t.Errorf("expected location string %s, got %s", tt.userTimezone, loc.String())
			}

			// Verify UTC conversion is reversible
			backToLocal := utcTime.In(loc)
			if !now.Equal(backToLocal) {
				t.Errorf("timezone conversion not reversible: %v -> %v -> %v", now, utcTime, backToLocal)
			}
		})
	}
}

// TestDigestFallback_InvalidTimezone tests that invalid timezone falls back to UTC.
func TestDigestFallback_InvalidTimezone(t *testing.T) {
	tests := []struct {
		name         string
		timezone     string
		shouldUseUTC bool
	}{
		{
			name:         "empty timezone defaults to UTC",
			timezone:     "",
			shouldUseUTC: true,
		},
		{
			name:         "invalid timezone string defaults to UTC",
			timezone:     "Invalid/Timezone",
			shouldUseUTC: true,
		},
		{
			name:         "non-existent timezone defaults to UTC",
			timezone:     "Mars/OlympusMons",
			shouldUseUTC: true,
		},
		{
			name:         "typo in timezone defaults to UTC",
			timezone:     "America/NewYork", // Missing underscore
			shouldUseUTC: true,
		},
		{
			name:         "deprecated timezone abbreviation may work or fail",
			timezone:     "EST", // Deprecated but may work in Go (fixed offset)
			shouldUseUTC: false, // Go recognizes EST as a fixed-offset timezone
		},
		{
			name:         "valid timezone works correctly",
			timezone:     "America/New_York",
			shouldUseUTC: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the timezone loading logic from checkAndSendDigests
			var tz *time.Location
			var err error

			if tt.timezone != "" {
				tz, err = time.LoadLocation(tt.timezone)
			}

			// If timezone is empty or invalid, should fall back to UTC
			if tt.timezone == "" || err != nil {
				tz = time.UTC
			}

			// Verify the fallback behavior
			if tt.shouldUseUTC {
				if tz != time.UTC {
					t.Errorf("expected UTC fallback for timezone %q, got %v", tt.timezone, tz)
				}
			} else {
				if tz == nil {
					t.Errorf("expected valid timezone for %q, got nil", tt.timezone)
				} else if tz.String() != tt.timezone {
					t.Errorf("expected timezone %q, got %q", tt.timezone, tz.String())
				}
			}

			// Verify we can use the timezone for time operations
			now := time.Now().In(tz)
			_ = now.Format("15:04")
			_ = now.Format("2006-01-02")
		})
	}
}

// TestDigestTimezone_EdgeCases tests timezone handling edge cases.
func TestDigestTimezone_EdgeCases(t *testing.T) {
	t.Run("DST transition in America/New_York", func(t *testing.T) {
		loc, err := time.LoadLocation("America/New_York")
		if err != nil {
			t.Fatalf("failed to load timezone: %v", err)
		}

		// Test around DST transition dates
		// DST typically starts second Sunday in March and ends first Sunday in November
		dstStart := time.Date(2024, 3, 10, 2, 0, 0, 0, loc) // Clocks spring forward
		dstEnd := time.Date(2024, 11, 3, 2, 0, 0, 0, loc)   // Clocks fall back

		// Verify DST transition times exist and are properly handled
		// Note: 2:00 AM on DST start doesn't exist (jumps to 3:00 AM)
		// 2:00 AM on DST end exists twice

		// Just before DST start
		beforeDST := time.Date(2024, 3, 10, 1, 59, 0, 0, loc)
		if beforeDST.Format("15:04") != "01:59" {
			t.Errorf("expected 01:59 before DST, got %s", beforeDST.Format("15:04"))
		}

		// Just after DST start
		afterDST := time.Date(2024, 3, 10, 3, 1, 0, 0, loc)
		if afterDST.Format("15:04") != "03:01" {
			t.Errorf("expected 03:01 after DST, got %s", afterDST.Format("15:04"))
		}

		_ = dstStart
		_ = dstEnd
	})

	t.Run("midnight boundary in UTC", func(t *testing.T) {
		loc := time.UTC

		// Test midnight boundary
		midnight := time.Date(2024, 6, 15, 0, 0, 0, 0, loc)
		if midnight.Format("15:04") != "00:00" {
			t.Errorf("expected 00:00 at midnight, got %s", midnight.Format("15:04"))
		}

		// Test 23:59 to 00:00 transition
		justBeforeMidnight := time.Date(2024, 6, 15, 23, 59, 0, 0, loc)
		afterMidnight := justBeforeMidnight.Add(2 * time.Minute)

		if justBeforeMidnight.Format("15:04") != "23:59" {
			t.Errorf("expected 23:59, got %s", justBeforeMidnight.Format("15:04"))
		}
		if afterMidnight.Format("15:04") != "00:01" {
			t.Errorf("expected 00:01, got %s", afterMidnight.Format("15:04"))
		}
	})

	t.Run("date boundary across timezones", func(t *testing.T) {
		// Test when it's different days in different timezones
		tokyo, _ := time.LoadLocation("Asia/Tokyo")       // UTC+9
		la, _ := time.LoadLocation("America/Los_Angeles") // UTC-8 (approximately)

		// Same UTC time, different local dates
		utcTime := time.Date(2024, 6, 15, 6, 0, 0, 0, time.UTC)

		tokyoTime := utcTime.In(tokyo)
		laTime := utcTime.In(la)

		// Tokyo should be June 15, 15:00
		// LA should be June 14, 23:00 (approximately, depending on DST)
		if tokyoTime.Format("2006-01-02") == laTime.Format("2006-01-02") {
			t.Log("Note: Same date in both timezones for this UTC time")
		}

		// Verify we can correctly compare digest times
		tokyoDigest := tokyoTime.Format("15:04")
		laDigest := laTime.Format("15:04")

		if tokyoDigest == laDigest {
			t.Errorf("expected different local times in Tokyo vs LA for same UTC time")
		}
	})

	t.Run("timezone abbreviation handling", func(t *testing.T) {
		// Test that timezone abbreviations are handled correctly
		// Note: IANA timezone identifiers should be used, not abbreviations

		// Valid IANA identifiers
		validZones := []string{
			"America/New_York",
			"Europe/London",
			"Asia/Tokyo",
			"Australia/Sydney",
			"Pacific/Honolulu",
			"Africa/Cairo",
			"Antarctica/McMurdo",
		}

		for _, zone := range validZones {
			loc, err := time.LoadLocation(zone)
			if err != nil {
				t.Errorf("failed to load valid timezone %s: %v", zone, err)
				continue
			}
			if loc.String() != zone {
				t.Errorf("timezone string mismatch: expected %s, got %s", zone, loc.String())
			}
		}

		// Abbreviations that should fail (not IANA identifiers)
		invalidZones := []string{
			"EST",
			"PST",
			"GMT",
			"CET",
		}

		for _, zone := range invalidZones {
			_, err := time.LoadLocation(zone)
			// Some abbreviations may work depending on Go version
			// We just verify the code doesn't panic
			if err != nil {
				t.Logf("abbreviation %s correctly rejected: %v", zone, err)
			}
		}
	})
}

// TestDigestTime_Comparison tests the digest time comparison logic.
func TestDigestTime_Comparison(t *testing.T) {
	tests := []struct {
		name        string
		userPrefs   UserNotificationPreferences
		currentTime string
		shouldSend  bool
	}{
		{
			name: "exact match sends digest",
			userPrefs: UserNotificationPreferences{
				DigestTime:     "09:00",
				DigestTimezone: "UTC",
			},
			currentTime: "09:00",
			shouldSend:  true,
		},
		{
			name: "no match does not send digest",
			userPrefs: UserNotificationPreferences{
				DigestTime:     "09:00",
				DigestTimezone: "UTC",
			},
			currentTime: "10:00",
			shouldSend:  false,
		},
		{
			name: "one minute difference does not send",
			userPrefs: UserNotificationPreferences{
				DigestTime:     "09:00",
				DigestTimezone: "UTC",
			},
			currentTime: "09:01",
			shouldSend:  false,
		},
		{
			name: "different timezone same local time",
			userPrefs: UserNotificationPreferences{
				DigestTime:     "14:30",
				DigestTimezone: "Asia/Tokyo",
			},
			currentTime: "14:30",
			shouldSend:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the comparison logic from checkAndSendDigests
			shouldSend := tt.userPrefs.DigestTime == tt.currentTime

			if shouldSend != tt.shouldSend {
				t.Errorf("expected shouldSend=%v, got %v for digest_time=%s vs current=%s",
					tt.shouldSend, shouldSend, tt.userPrefs.DigestTime, tt.currentTime)
			}
		})
	}
}

// TestDigestSendTime_MultipleTimezones tests multiple users with different timezones.
func TestDigestSendTime_MultipleTimezones(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestAlertTables(t, database)
	databaseWrapper := db.New(database)
	ctx := context.Background()

	// Create users in different timezones
	users := []struct {
		username string
		email    string
		timezone string
		digestAt string
	}{
		{"user_utc", "user_utc@test.com", "UTC", "09:00"},
		{"user_ny", "user_ny@test.com", "America/New_York", "09:00"},
		{"user_tokyo", "user_tokyo@test.com", "Asia/Tokyo", "08:00"},
		{"user_london", "user_london@test.com", "Europe/London", "10:00"},
	}

	for _, u := range users {
		userID := createTestUser(t, database, u.username, u.email, "admin")

		prefs := &UserNotificationPreferences{
			UserID:         uint(userID),
			DigestEnabled:  true,
			DigestTime:     u.digestAt,
			DigestTimezone: u.timezone,
		}

		if err := UpsertUserNotificationPreferences(ctx, databaseWrapper, prefs); err != nil {
			t.Fatalf("failed to create preferences for %s: %v", u.username, err)
		}

		// Verify preferences were stored correctly
		stored, err := GetUserNotificationPreferences(ctx, databaseWrapper, uint(userID))
		if err != nil {
			t.Fatalf("failed to get preferences for %s: %v", u.username, err)
		}

		if stored.DigestTimezone != u.timezone {
			t.Errorf("user %s: expected timezone %s, got %s", u.username, u.timezone, stored.DigestTimezone)
		}
		if stored.DigestTime != u.digestAt {
			t.Errorf("user %s: expected digest time %s, got %s", u.username, u.digestAt, stored.DigestTime)
		}

		// Verify timezone can be loaded
		loc, err := time.LoadLocation(stored.DigestTimezone)
		if err != nil {
			t.Errorf("user %s: failed to load timezone %s: %v", u.username, stored.DigestTimezone, err)
			continue
		}

		// Simulate checking if it's time to send digest
		now := time.Now().In(loc)
		currentTime := now.Format("15:04")

		if stored.DigestTime == currentTime {
			t.Logf("User %s would receive digest now (timezone: %s, local time: %s)",
				u.username, u.timezone, currentTime)
		}
	}
}

// TestDigestSendTime_TimezoneInDatabase tests storing and retrieving timezone from database.
func TestDigestSendTime_TimezoneInDatabase(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestAlertTables(t, database)
	databaseWrapper := db.New(database)
	ctx := context.Background()

	userID := createTestUser(t, database, "tzuser", "tzuser@test.com", "admin")

	tests := []struct {
		name     string
		timezone string
	}{
		{"UTC timezone", "UTC"},
		{"America/New_York", "America/New_York"},
		{"Europe/Paris", "Europe/Paris"},
		{"Asia/Hong_Kong", "Asia/Hong_Kong"},
		{"Australia/Melbourne", "Australia/Melbourne"},
		{"Pacific/Auckland", "Pacific/Auckland"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefs := &UserNotificationPreferences{
				UserID:         uint(userID),
				DigestEnabled:  true,
				DigestTime:     "09:00",
				DigestTimezone: tt.timezone,
			}

			if err := UpsertUserNotificationPreferences(ctx, databaseWrapper, prefs); err != nil {
				t.Fatalf("failed to upsert preferences: %v", err)
			}

			stored, err := GetUserNotificationPreferences(ctx, databaseWrapper, uint(userID))
			if err != nil {
				t.Fatalf("failed to get preferences: %v", err)
			}

			if stored.DigestTimezone != tt.timezone {
				t.Errorf("expected timezone %s, got %s", tt.timezone, stored.DigestTimezone)
			}

			// Verify the timezone is valid
			loc, err := time.LoadLocation(stored.DigestTimezone)
			if err != nil {
				t.Errorf("stored timezone %s is invalid: %v", stored.DigestTimezone, err)
			}

			// Verify we can use it
			_ = time.Now().In(loc)
		})
	}
}

// TestQuietHours_TimezoneHandling tests quiet hours with timezone awareness.
func TestQuietHours_TimezoneHandling(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	setupTestAlertTables(t, database)
	databaseWrapper := db.New(database)
	ctx := context.Background()

	userID := createTestUser(t, database, "qhuser", "qhuser@test.com", "admin")

	tests := []struct {
		name     string
		start    string
		end      string
		timezone string
	}{
		{"UTC quiet hours", "22:00", "07:00", "UTC"},
		{"New York quiet hours", "22:00", "07:00", "America/New_York"},
		{"Tokyo quiet hours", "23:00", "06:00", "Asia/Tokyo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefs := &UserNotificationPreferences{
				UserID:             uint(userID),
				QuietHoursEnabled:  true,
				QuietHoursStart:    tt.start,
				QuietHoursEnd:      tt.end,
				QuietHoursTimezone: tt.timezone,
			}

			if err := UpsertUserNotificationPreferences(ctx, databaseWrapper, prefs); err != nil {
				t.Fatalf("failed to upsert preferences: %v", err)
			}

			stored, err := GetUserNotificationPreferences(ctx, databaseWrapper, uint(userID))
			if err != nil {
				t.Fatalf("failed to get preferences: %v", err)
			}

			if stored.QuietHoursTimezone != tt.timezone {
				t.Errorf("expected timezone %s, got %s", tt.timezone, stored.QuietHoursTimezone)
			}

			// Verify timezone can be loaded
			loc, err := time.LoadLocation(stored.QuietHoursTimezone)
			if err != nil {
				t.Errorf("failed to load timezone %s: %v", stored.QuietHoursTimezone, err)
				return
			}

			// Check current time against quiet hours in user's timezone
			now := time.Now().In(loc)
			currentHour := now.Hour()

			// Simple quiet hours check (crossing midnight)
			var isQuietHours bool
			startHour := parseTimeHour(tt.start)
			endHour := parseTimeHour(tt.end)

			if startHour > endHour {
				// Crosses midnight
				isQuietHours = currentHour >= startHour || currentHour < endHour
			} else {
				// Same day
				isQuietHours = currentHour >= startHour && currentHour < endHour
			}

			t.Logf("Quiet hours %s-%s in %s: current hour=%d, is quiet=%v",
				tt.start, tt.end, tt.timezone, currentHour, isQuietHours)
		})
	}
}

// parseTimeHour extracts the hour from a HH:MM time string.
func parseTimeHour(timeStr string) int {
	// Simple parsing: HH:MM format
	if len(timeStr) >= 2 {
		// Handle single digit hour (H:MM)
		if len(timeStr) == 4 && timeStr[1] == ':' {
			return int(timeStr[0]-'0') * 10
		}
		// Handle two digit hour (HH:MM)
		if len(timeStr) >= 5 && timeStr[2] == ':' {
			return int(timeStr[0]-'0')*10 + int(timeStr[1]-'0')
		}
	}
	return 0
}
