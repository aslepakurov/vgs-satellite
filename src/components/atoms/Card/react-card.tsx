import React from 'react';
import classNames from 'classnames';

export interface ICardProps {
  title: string | JSX.Element;
  children?: React.Component | JSX.Element | boolean;
  className?: string;
  footer?: string | JSX.Element;
  headerColor?: string;
}

const ReactCard: React.SFC<ICardProps> = (props) => {
  return (
    <div className={classNames({ [String(props.className)]: props.className }, 'card')}>
      { props.title && (
      <div className={classNames(props.headerColor, 'card-header')}>{props.title}</div>
      )
    }
      { props.children &&
        <div className="card-body">{props.children}</div>
      }
      { props.footer &&
        <>
          <hr className="mx-3 my-0"/>
          <div className="card-footer">
            {props.footer}
          </div>
        </>
      }
    </div>
  );
};
export default ReactCard;
