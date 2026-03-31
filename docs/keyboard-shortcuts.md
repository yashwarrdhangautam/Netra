# Keyboard Shortcuts - NETRA Dashboard

Quick reference for keyboard shortcuts in the NETRA dashboard.

## 🎹 Available Shortcuts

### Navigation

| Shortcut | Action |
|----------|--------|
| `G` | Go to Dashboard |
| `S` | Go to Scans |
| `F` | Go to Findings |
| `R` | Go to Reports |
| `/` | Focus Search |

### Actions

| Shortcut | Action |
|----------|--------|
| `N` | New Scan |
| `R` | Generate Report |

### Help

| Shortcut | Action |
|----------|--------|
| `?` | Show Keyboard Shortcuts Help |
| `Esc` | Close Modal / Cancel Search |

## 💡 Usage Tips

1. **Avoid conflicts**: Shortcuts are disabled when typing in input fields or textareas
2. **Quick navigation**: Press `G` then `S` to quickly go from Dashboard to Scans
3. **Search fast**: Press `/` to instantly focus the search bar
4. **Help always available**: Press `?` anytime to view this reference
5. **Close modals**: Press `Esc` to close any open modal or cancel a search

## 🔧 Implementation

### Files Modified/Created

- `frontend/src/hooks/useKeyboardShortcuts.ts` - Hook for keyboard event handling
- `frontend/src/components/shared/KeyboardShortcutsModal.tsx` - Help modal component
- `frontend/src/components/layout/Layout.tsx` - Global integration
- `frontend/src/components/layout/Header.tsx` - Help button in header

### Adding Custom Shortcuts

To add a new shortcut, update the `shortcuts` array in `useKeyboardShortcuts.ts`:

```typescript
{
  key: 'X',
  handler: () => {
    // Your action here
    console.log('Shortcut X triggered')
  },
  description: 'Custom Action',
  category: 'Actions',
}
```

### Event System

The keyboard shortcuts use a custom event system for decoupled communication:

- `netra:new-scan` - Trigger new scan
- `netra:show-shortcuts` - Show shortcuts modal
- `netra:generate-report` - Trigger report generation
- `netra:close-modal` - Close any open modal

Listen for these events in your components:

```typescript
useEffect(() => {
  const handleNewScan = () => {
    // Open new scan modal
  }
  
  window.addEventListener('netra:new-scan', handleNewScan)
  return () => window.removeEventListener('netra:new-scan', handleNewScan)
}, [])
```

## ♿ Accessibility

- All shortcuts are discoverable via the `?` key
- Visual feedback shown in the modal
- Shortcuts respect focus management (disabled in inputs)
- ARIA labels on all interactive elements

## 🎨 Styling

The modal uses Tailwind CSS with:
- Dark/light theme support
- Smooth animations (fade-in, zoom-in)
- Responsive design
- Accessible focus states

## 📱 Mobile Support

Keyboard shortcuts are **desktop-only** feature. On mobile/tablet:
- Shortcuts are disabled
- Help button still visible for reference
- Use touch navigation instead

## 🐛 Troubleshooting

**Shortcuts not working?**
- Check if you're typing in an input field
- Ensure no browser extensions are blocking keyboard events
- Try refreshing the page

**Modal not opening?**
- Check browser console for errors
- Ensure JavaScript is enabled
- Try clicking the help icon (?) in the header

## 📝 Future Enhancements

Planned improvements:
- [ ] Customizable key bindings (Settings page)
- [ ] Vim-style navigation mode
- [ ] Shortcut hints on hover
- [ ] Recent pages quick switch (Cmd+K / Ctrl+K)
- [ ] Macro support (sequence of actions)

---

**Added**: March 29, 2026  
**Version**: 1.0.0  
**Maintained By**: @yashwarrdhangautam
