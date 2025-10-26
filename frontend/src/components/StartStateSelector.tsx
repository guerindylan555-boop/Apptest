/**
 * Start State Tag Selector Component
 *
 * Allows operators to tag captured screens with their start-state profile.
 * Supports the four main start states: clean, logged_out_home, logged_in_no_rental, logged_in_with_rental.
 */

import React, { useState } from 'react';

export type StartStateTag =
  | 'clean'
  | 'logged_out_home'
  | 'logged_in_no_rental'
  | 'logged_in_with_rental'
  | 'other';

export interface StartStateOption {
  value: StartStateTag;
  label: string;
  description: string;
  color: string;
  icon: React.ReactNode;
}

interface StartStateSelectorProps {
  selectedState?: StartStateTag;
  onStateChange: (state: StartStateTag) => void;
  disabled?: boolean;
  showOtherOption?: boolean;
  className?: string;
}

export const StartStateSelector: React.FC<StartStateSelectorProps> = ({
  selectedState,
  onStateChange,
  disabled = false,
  showOtherOption = true,
  className = '',
}) => {
  const [customDescription, setCustomDescription] = useState('');

  const startStateOptions: StartStateOption[] = [
    {
      value: 'clean',
      label: 'Clean Boot',
      description: 'Fresh app launch, no user session',
      color: 'blue',
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
      ),
    },
    {
      value: 'logged_out_home',
      label: 'Logged Out',
      description: 'App home screen without user authentication',
      color: 'gray',
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
        </svg>
      ),
    },
    {
      value: 'logged_in_no_rental',
      label: 'Logged In - No Rental',
      description: 'User authenticated, no active scooter rental',
      color: 'green',
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
    },
    {
      value: 'logged_in_with_rental',
      label: 'Logged In - With Rental',
      description: 'User authenticated with active scooter rental',
      color: 'purple',
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v13m0-13V6a2 2 0 112 2h-2zm0 0V5.5A2.5 2.5 0 109.5 8H12zm-7 4h14M5 12a2 2 0 110-4h14a2 2 0 110 4M5 12v7a2 2 0 002 2h10a2 2 0 002-2v-7" />
        </svg>
      ),
    },
  ];

  if (showOtherOption) {
    startStateOptions.push({
      value: 'other',
      label: 'Other',
      description: 'Custom state not covered by standard categories',
      color: 'orange',
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
        </svg>
      ),
    });
  }

  const getColorClasses = (color: string, isSelected: boolean) => {
    const baseClasses = 'border-2 rounded-lg p-4 cursor-pointer transition-all duration-200 ';

    if (!isSelected) {
      switch (color) {
        case 'blue':
          return baseClasses + 'border-gray-200 hover:border-blue-300 hover:bg-blue-50';
        case 'gray':
          return baseClasses + 'border-gray-200 hover:border-gray-300 hover:bg-gray-50';
        case 'green':
          return baseClasses + 'border-gray-200 hover:border-green-300 hover:bg-green-50';
        case 'purple':
          return baseClasses + 'border-gray-200 hover:border-purple-300 hover:bg-purple-50';
        case 'orange':
          return baseClasses + 'border-gray-200 hover:border-orange-300 hover:bg-orange-50';
        default:
          return baseClasses + 'border-gray-200 hover:border-gray-300 hover:bg-gray-50';
      }
    }

    switch (color) {
      case 'blue':
        return baseClasses + 'border-blue-500 bg-blue-50';
      case 'gray':
        return baseClasses + 'border-gray-500 bg-gray-50';
      case 'green':
        return baseClasses + 'border-green-500 bg-green-50';
      case 'purple':
        return baseClasses + 'border-purple-500 bg-purple-50';
      case 'orange':
        return baseClasses + 'border-orange-500 bg-orange-50';
      default:
        return baseClasses + 'border-gray-500 bg-gray-50';
    }
  };

  const getIconColorClasses = (color: string, isSelected: boolean) => {
    if (!isSelected) {
      switch (color) {
        case 'blue':
          return 'text-gray-400 group-hover:text-blue-600';
        case 'gray':
          return 'text-gray-400 group-hover:text-gray-600';
        case 'green':
          return 'text-gray-400 group-hover:text-green-600';
        case 'purple':
          return 'text-gray-400 group-hover:text-purple-600';
        case 'orange':
          return 'text-gray-400 group-hover:text-orange-600';
        default:
          return 'text-gray-400 group-hover:text-gray-600';
      }
    }

    switch (color) {
      case 'blue':
        return 'text-blue-600';
      case 'gray':
        return 'text-gray-600';
      case 'green':
        return 'text-green-600';
      case 'purple':
        return 'text-purple-600';
      case 'orange':
        return 'text-orange-600';
      default:
        return 'text-gray-600';
    }
  };

  const handleStateSelect = (state: StartStateTag) => {
    if (disabled) return;
    onStateChange(state);
  };

  return (
    <div className={`space-y-4 ${className}`}>
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2">
          Start State Tag
        </label>
        <p className="text-xs text-gray-500 mb-4">
          Select the start state profile for this screen. This helps flow routing and detection.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {startStateOptions.map((option) => {
          const isSelected = selectedState === option.value;
          return (
            <div
              key={option.value}
              className={`group ${getColorClasses(option.color, isSelected)} ${
                disabled ? 'opacity-50 cursor-not-allowed' : ''
              }`}
              onClick={() => handleStateSelect(option.value)}
            >
              <div className="flex items-start space-x-3">
                <div className={getIconColorClasses(option.color, isSelected)}>
                  {option.icon}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <h4 className="text-sm font-medium text-gray-900">
                      {option.label}
                    </h4>
                    {isSelected && (
                      <div className="flex-shrink-0">
                        <svg className="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                        </svg>
                      </div>
                    )}
                  </div>
                  <p className="text-xs text-gray-500 mt-1">
                    {option.description}
                  </p>
                </div>
              </div>

              {/* Custom description for "Other" option */}
              {option.value === 'other' && isSelected && (
                <div className="mt-3 pt-3 border-t border-gray-200">
                  <label className="block text-xs font-medium text-gray-700 mb-1">
                    Custom Description
                  </label>
                  <input
                    type="text"
                    value={customDescription}
                    onChange={(e) => setCustomDescription(e.target.value)}
                    placeholder="Describe this custom state..."
                    className="w-full px-2 py-1 text-xs border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-orange-500 focus:border-orange-500"
                    disabled={disabled}
                  />
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Selected State Summary */}
      {selectedState && (
        <div className="mt-4 p-3 bg-gray-50 rounded-lg">
          <div className="flex items-center space-x-2">
            <span className="text-sm font-medium text-gray-700">Selected:</span>
            <span className="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-gray-200 text-gray-800">
              {startStateOptions.find(opt => opt.value === selectedState)?.label}
            </span>
            {selectedState === 'other' && customDescription && (
              <span className="text-xs text-gray-500">({customDescription})</span>
            )}
          </div>
        </div>
      )}

      {/* Help Text */}
      <div className="mt-4 p-3 bg-blue-50 rounded-lg">
        <div className="flex">
          <div className="flex-shrink-0">
            <svg className="h-4 w-4 text-blue-400" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
            </svg>
          </div>
          <div className="ml-2">
            <p className="text-xs text-blue-800">
              <strong>Why this matters:</strong> Start state tags help the flow runner choose the correct
              path and unlock policies (e.g., "any_available" vs "existing_rental_only").
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default StartStateSelector;