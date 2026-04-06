package db

import (
	"context"
	"database/sql"
	"fmt"

	"runic/internal/common/log"
)

// seedSystemServices creates default system services if they don't exist.
// System services are non-deletable and provide essential firewall functionality.
func seedSystemServices(ctx context.Context, database *sql.DB) error {
	// Define system services to seed
	systemServices := []struct {
		Name        string
		Ports       string
		SourcePorts string
		Protocol    string
		Description string
		NoConntrack bool
	}{
		{
			Name:        "ICMP",
			Ports:       "",
			SourcePorts: "",
			Protocol:    "icmp",
			Description: "ICMP protocol for ping and network diagnostics (system service)",
			NoConntrack: false,
		},
		{
			Name:        "IGMP",
			Ports:       "",
			SourcePorts: "",
			Protocol:    "igmp",
			Description: "IGMP protocol for multicast group management (system service)",
			NoConntrack: true,
		},
		{
			Name:        "Multicast",
			Ports:       "",
			SourcePorts: "",
			Protocol:    "udp",
			Description: "Multicast traffic handling (system service)",
			NoConntrack: true,
		},
		{
			Name:        "mDNS",
			Ports:       "5353",
			SourcePorts: "5353",
			Protocol:    "udp",
			Description: "Multicast DNS for local network service discovery (system service)",
			NoConntrack: true,
		},
	}

	for _, svc := range systemServices {
		// Check if service already exists
		var count int
		err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM services WHERE name = ?", svc.Name).Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to check for existing service %s: %w", svc.Name, err)
		}

		if count > 0 {
			// Service exists, ensure it's marked as system service and update no_conntrack
			_, err := database.ExecContext(ctx, "UPDATE services SET is_system = 1, no_conntrack = ? WHERE name = ?", svc.NoConntrack, svc.Name)
			if err != nil {
				return fmt.Errorf("failed to update system flag for service %s: %w", svc.Name, err)
			}
			log.Info("Seeding: ensured system service", "service", svc.Name)
			continue
		}

		// Insert new system service
		_, err = database.ExecContext(ctx,
			"INSERT INTO services (name, ports, source_ports, protocol, description, is_system, no_conntrack) VALUES (?, ?, ?, ?, ?, 1, ?)",
			svc.Name, svc.Ports, svc.SourcePorts, svc.Protocol, svc.Description, svc.NoConntrack,
		)
		if err != nil {
			return fmt.Errorf("failed to create system service %s: %w", svc.Name, err)
		}
		log.Info("Seeding: created system service", "service", svc.Name)
	}

	return nil
}

// seedSystemGroups creates default system groups if they don't exist.
// System groups are non-deletable and provide essential group functionality.
func seedSystemGroups(ctx context.Context, database *sql.DB) error {
	// Define system groups to seed
	systemGroups := []struct {
		Name        string
		Description string
	}{
		{
			Name:        "localhost",
			Description: "Virtual group for local traffic (127.0.0.1/8)",
		},
	}

	for _, grp := range systemGroups {
		// Check if group already exists
		var count int
		err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM groups WHERE name = ?", grp.Name).Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to check for existing group %s: %w", grp.Name, err)
		}

		if count > 0 {
			// Group exists, ensure it's marked as system group
			_, err := database.ExecContext(ctx, "UPDATE groups SET is_system = 1 WHERE name = ?", grp.Name)
			if err != nil {
				return fmt.Errorf("failed to update system flag for group %s: %w", grp.Name, err)
			}
			log.Info("Seeding: ensured system group", "group", grp.Name)
			continue
		}

		// Insert new system group
		_, err = database.ExecContext(ctx,
			"INSERT INTO groups (name, description, is_system) VALUES (?, ?, 1)",
			grp.Name, grp.Description,
		)
		if err != nil {
			return fmt.Errorf("failed to create system group %s: %w", grp.Name, err)
		}
		log.Info("Seeding: created system group", "group", grp.Name)
	}

	return nil
}
