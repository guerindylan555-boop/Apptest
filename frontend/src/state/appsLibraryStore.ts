import { create } from 'zustand';
import type { ApkEntry, UploadProgress } from '../types/apps';

/**
 * Apps Library Store
 *
 * Manages state for the APK library, including entries, selection, and upload progress.
 */

export interface AppsLibraryState {
  /** All APK entries */
  entries: ApkEntry[];

  /** Currently selected APK entry ID */
  selectedEntryId: string | null;

  /** Current upload progress (null when not uploading) */
  uploadProgress: UploadProgress | null;

  /** Search filter text */
  searchFilter: string;

  /** Sort configuration */
  sortBy: 'uploadedAt' | 'lastUsedAt' | 'displayName' | 'packageName';
  sortOrder: 'asc' | 'desc';

  /** Loading state */
  isLoading: boolean;

  /** Error state */
  error: string | null;

  // Actions
  setEntries: (entries: ApkEntry[]) => void;
  addEntry: (entry: ApkEntry) => void;
  updateEntry: (id: string, updates: Partial<ApkEntry>) => void;
  removeEntry: (id: string) => void;
  setSelectedEntryId: (id: string | null) => void;
  setUploadProgress: (progress: UploadProgress | null) => void;
  setSearchFilter: (filter: string) => void;
  setSorting: (sortBy: AppsLibraryState['sortBy'], sortOrder: AppsLibraryState['sortOrder']) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
}

export const useAppsLibraryStore = create<AppsLibraryState>((set) => ({
  entries: [],
  selectedEntryId: null,
  uploadProgress: null,
  searchFilter: '',
  sortBy: 'uploadedAt',
  sortOrder: 'desc',
  isLoading: false,
  error: null,

  setEntries: (entries) => set({ entries }),

  addEntry: (entry) =>
    set((state) => ({
      entries: [...state.entries, entry]
    })),

  updateEntry: (id, updates) =>
    set((state) => ({
      entries: state.entries.map((entry) =>
        entry.id === id ? { ...entry, ...updates } : entry
      )
    })),

  removeEntry: (id) =>
    set((state) => ({
      entries: state.entries.filter((entry) => entry.id !== id),
      selectedEntryId: state.selectedEntryId === id ? null : state.selectedEntryId
    })),

  setSelectedEntryId: (id) => set({ selectedEntryId: id }),

  setUploadProgress: (progress) => set({ uploadProgress: progress }),

  setSearchFilter: (filter) => set({ searchFilter: filter }),

  setSorting: (sortBy, sortOrder) => set({ sortBy, sortOrder }),

  setLoading: (loading) => set({ isLoading: loading }),

  setError: (error) => set({ error })
}));

/**
 * Selector: Get the currently selected entry
 */
export function useSelectedEntry(): ApkEntry | null {
  const entries = useAppsLibraryStore((state) => state.entries);
  const selectedId = useAppsLibraryStore((state) => state.selectedEntryId);

  if (!selectedId) return null;
  return entries.find((e) => e.id === selectedId) || null;
}

/**
 * Selector: Get filtered and sorted entries
 */
export function useFilteredEntries(): ApkEntry[] {
  const entries = useAppsLibraryStore((state) => state.entries);
  const searchFilter = useAppsLibraryStore((state) => state.searchFilter);
  const sortBy = useAppsLibraryStore((state) => state.sortBy);
  const sortOrder = useAppsLibraryStore((state) => state.sortOrder);

  // Filter
  let filtered = entries;
  if (searchFilter) {
    const search = searchFilter.toLowerCase();
    filtered = entries.filter(
      (e) =>
        e.displayName.toLowerCase().includes(search) ||
        e.packageName.toLowerCase().includes(search)
    );
  }

  // Sort
  const sorted = [...filtered].sort((a, b) => {
    const aVal = a[sortBy];
    const bVal = b[sortBy];

    if (aVal === null && bVal === null) return 0;
    if (aVal === null) return 1;
    if (bVal === null) return -1;

    let comparison = 0;
    if (typeof aVal === 'string' && typeof bVal === 'string') {
      comparison = aVal.localeCompare(bVal);
    } else if (aVal < bVal) {
      comparison = -1;
    } else if (aVal > bVal) {
      comparison = 1;
    }

    return sortOrder === 'desc' ? -comparison : comparison;
  });

  return sorted;
}
