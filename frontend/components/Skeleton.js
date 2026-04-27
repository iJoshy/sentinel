import React from 'react';

/**
 * A reusable Skeleton component for loading states.
 * Use specialized variants for common shapes.
 */
export function Skeleton({ className = '', style = {} }) {
  return <div className={`skeleton ${className}`} style={style} />;
}

export function SkeletonText({ lines = 3, className = '', style = {}, ...props }) {
  return (
    <div className={`skeleton-container ${className}`} style={style} {...props}>
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton 
          key={i} 
          className="skeleton-text" 
          style={{ width: i === lines - 1 && lines > 1 ? '70%' : '100%' }} 
        />
      ))}
    </div>
  );
}

export function SkeletonTitle({ className = '', ...props }) {
  return <Skeleton className={`skeleton-title ${className}`} {...props} />;
}

export function SkeletonRect({ height = 100, className = '', style = {}, ...props }) {
  return <Skeleton className={`skeleton-rect ${className}`} style={{ height, ...style }} {...props} />;
}

export function SkeletonCircle({ size = 40, className = '', style = {}, ...props }) {
  return <Skeleton className={`skeleton-circle ${className}`} style={{ width: size, height: size, ...style }} {...props} />;
}

export default Skeleton;
